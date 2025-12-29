import logging
import time
from enum import Enum, IntEnum
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

try:
    from zoneinfo import ZoneInfo
except Exception:
    from backports.zoneinfo import ZoneInfo  # type: ignore

import requests

logger = logging.getLogger(__name__)

# New iQua API base (found via DevTools)
DEFAULT_API_BASE_URL = "https://api.myiquaapp.com/v1"
DEFAULT_USER_AGENT = "Mozilla/5.0 (HomeAssistant; iqua-softener) requests"

DEFAULT_TIMEOUT_SECONDS = 20
RETRY_BACKOFF_SECONDS = 1.0
RETRY_MAX_ATTEMPTS = 3


class IquaSoftenerState(str, Enum):
    ONLINE = "Online"
    OFFLINE = "Offline"


class IquaSoftenerVolumeUnit(IntEnum):
    GALLONS = 0
    LITERS = 1


class IquaSoftenerException(Exception):
    pass


@dataclass(frozen=True)
class IquaSoftenerData:
    timestamp: datetime
    model: str
    state: IquaSoftenerState
    device_date_time: datetime
    volume_unit: IquaSoftenerVolumeUnit
    current_water_flow: float
    today_use: int
    average_daily_use: int
    total_water_available: int
    days_since_last_regeneration: int
    salt_level: int
    salt_level_percent: int
    out_of_salt_estimated_days: int
    hardness_grains: int
    water_shutoff_valve_state: int


class IquaSoftener:
    """
    Updated client for api.myiquaapp.com.

    Auth:
      POST /auth/login with JSON { email, password }
      Response includes access_token, refresh_token

    Data:
      GET /devices/{uuid}/debug -> groups/items structure (DeviceDebugInfo)
      We map key values to the previously used IquaSoftenerData fields.
    """

    def __init__(
        self,
        username: str,
        password: str,
        device_serial_number: str,
        api_base_url: str = DEFAULT_API_BASE_URL,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        # Backward compatible: username is email now
        self._email: str = username
        self._password: str = password
        self._device_id: str = device_serial_number  # this is UUID in new system
        self._api_base_url: str = api_base_url.rstrip("/")
        self._user_agent: str = user_agent

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None

    @property
    def device_serial_number(self) -> str:
        # keep property name for old consumers
        return self._device_id

    # ----------------------------
    # Public API used by HA
    # ----------------------------

    def get_data(self) -> IquaSoftenerData:
        with requests.Session() as session:
            self._ensure_login(session)

            debug = self._get_device_debug(session)
            kv = self._extract_kv_map(debug)

            now = datetime.now()

            # Model
            model = kv.get("model") or "iQua"

            # Device/controller time
            controller_time = kv.get("controller_time")  # e.g. "16:37"
            # "time_message_received" is "29/12/2025 16:37" (dd/mm/yyyy hh:mm)
            received = kv.get("time_message_received")

            tz = ZoneInfo("Europe/Berlin")  # best-effort; API doesn't provide tz in debug payload you shared
            device_dt = self._parse_device_datetime(received, controller_time, tz, fallback=now)

            # Units
            volume_units = (kv.get("volume_units") or "").strip().lower()
            volume_unit = IquaSoftenerVolumeUnit.LITERS if "liter" in volume_units else IquaSoftenerVolumeUnit.GALLONS

            # Values we can map reliably from debug:
            # water_today, average_daily_use, treated_water_left, current_flow_rate
            today_use = self._to_int(kv.get("water_today"), default=0)
            avg_daily = self._to_int(kv.get("average_daily_use"), default=0)
            total_available = self._to_int(kv.get("treated_water_left"), default=0)
            current_flow = self._to_float(kv.get("current_flow_rate"), default=0.0)

            # Salt monitor
            salt_level_percent = self._to_int(kv.get("salt_monitor_level"), default=0)
            out_of_salt_days = self._to_int(kv.get("out_of_salt_days"), default=0)

            # Hardness (PPM). Old library used "grains" – we map PPM -> grains approx if needed.
            hardness_ppm = self._to_float(kv.get("hardness"), default=0.0)
            # 1 gpg (grain/gal) ≈ 17.1 ppm as CaCO3
            hardness_grains = int(round(hardness_ppm / 17.1)) if hardness_ppm else 0

            # Days since last regen: we have "time_since_last_recharge" in days (string "1")
            days_since_regen = self._to_int(kv.get("time_since_last_recharge"), default=0)

            # Salt level (absolute) isn't present directly in debug (you have salt_total etc.).
            # Keep as 0 unless you want "salt_total" (kg) to be used.
            salt_level = 0

            # Valve state: debug contains "valve_position" (Service/Backwash/...) but not explicit shutoff state.
            # Keep as 0 for compatibility.
            valve_state = 0

            # State: no explicit online/offline in debug. Use ONLINE as best-effort.
            state = IquaSoftenerState.ONLINE

            return IquaSoftenerData(
                timestamp=now,
                model=str(model),
                state=state,
                device_date_time=device_dt,
                volume_unit=volume_unit,
                current_water_flow=current_flow,
                today_use=today_use,
                average_daily_use=avg_daily,
                total_water_available=total_available,
                days_since_last_regeneration=days_since_regen,
                salt_level=salt_level,
                salt_level_percent=salt_level_percent,
                out_of_salt_estimated_days=out_of_salt_days,
                hardness_grains=hardness_grains,
                water_shutoff_valve_state=valve_state,
            )

    def set_water_shutoff_valve(self, state: int):
        # New API endpoint unknown; keep explicit message
        raise IquaSoftenerException(
            "set_water_shutoff_valve is not implemented for api.myiquaapp.com yet."
        )

    # ----------------------------
    # Auth + HTTP helpers
    # ----------------------------

    def _ensure_login(self, session: requests.Session) -> None:
        if self._access_token is None:
            self._login(session)

    def _login(self, session: requests.Session) -> None:
        url = self._get_url("auth/login")
        payload = {"email": self._email, "password": self._password}

        resp = self._request_with_retries(
            session,
            method="POST",
            url=url,
            headers=self._get_headers(with_auth=False),
            json=payload,
        )

        if resp.status_code != 200:
            raise IquaSoftenerException(f"Login failed: HTTP {resp.status_code}")

        data = resp.json()
        access = data.get("access_token")
        refresh = data.get("refresh_token")
        if not access:
            raise IquaSoftenerException(
                f"Login response missing access_token. Keys: {sorted(list(data.keys()))}"
            )
        self._access_token = access
        self._refresh_token = refresh

    def _request_with_retries(
        self,
        session: requests.Session,
        method: str,
        url: str,
        headers: Dict[str, str],
        json: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        backoff = RETRY_BACKOFF_SECONDS
        last_exc: Optional[Exception] = None

        for attempt in range(1, RETRY_MAX_ATTEMPTS + 1):
            try:
                resp = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json,
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )
                if resp.status_code in (502, 503, 504, 429):
                    logger.warning(
                        "HTTP %s on %s (attempt %s/%s)",
                        resp.status_code,
                        url,
                        attempt,
                        RETRY_MAX_ATTEMPTS,
                    )
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return resp
            except requests.exceptions.RequestException as ex:
                last_exc = ex
                logger.warning(
                    "Request exception on %s (attempt %s/%s): %s",
                    url,
                    attempt,
                    RETRY_MAX_ATTEMPTS,
                    ex,
                )
                time.sleep(backoff)
                backoff *= 2

        raise IquaSoftenerException(f"Request failed after retries: {url} ({last_exc})")

    def _authorized_get_json(self, session: requests.Session, url: str) -> Any:
        headers = self._get_headers(with_auth=True)
        resp = self._request_with_retries(session, "GET", url, headers=headers)

        if resp.status_code == 401:
            # re-login once
            self._access_token = None
            self._login(session)
            headers = self._get_headers(with_auth=True)
            resp = self._request_with_retries(session, "GET", url, headers=headers)

        if resp.status_code != 200:
            raise IquaSoftenerException(
                f"Invalid status ({resp.status_code}) for data request: {url}"
            )

        return resp.json()

    def _get_headers(self, with_auth: bool = True) -> Dict[str, str]:
        headers = {
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        if with_auth and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers

    def _get_url(self, resource: str) -> str:
        return f"{self._api_base_url}/{resource.lstrip('/')}"

    # ----------------------------
    # Data: debug endpoint + parsing
    # ----------------------------

    def _get_device_debug(self, session: requests.Session) -> Dict[str, Any]:
        url = self._get_url(f"devices/{self._device_id}/debug")
        data = self._authorized_get_json(session, url)
        if not isinstance(data, dict):
            raise IquaSoftenerException("Unexpected debug payload type.")
        return data

    def _extract_kv_map(self, debug_payload: Dict[str, Any]) -> Dict[str, str]:
        """
        Convert groups/items (kv + table) into a flat map:
          kv_map[item.key] = item_kv.value
        For tables we currently ignore; can be added later if desired.
        """
        kv_map: Dict[str, str] = {}
        groups = debug_payload.get("groups", [])
        if not isinstance(groups, list):
            return kv_map

        for g in groups:
            if not isinstance(g, dict):
                continue
            items = g.get("items", [])
            if not isinstance(items, list):
                continue
            for it in items:
                if not isinstance(it, dict):
                    continue
                it_key = it.get("key")
                it_type = it.get("type")
                if not it_key or not isinstance(it_key, str):
                    continue

                if it_type == "kv":
                    kv = it.get("item_kv", {})
                    if isinstance(kv, dict):
                        val = kv.get("value")
                        if val is None:
                            continue
                        kv_map[it_key] = str(val)
                # tables exist (water usage history), ignore for now

        return kv_map

    # ----------------------------
    # Parsing helpers
    # ----------------------------

    def _to_float(self, raw: Optional[str], default: float = 0.0) -> float:
        if raw is None:
            return default
        s = str(raw).strip()
        # strip units like "76.5%"
        s = s.replace("%", "").strip()
        # some values could include " Days"
        s = s.replace("Days", "").strip()
        try:
            return float(s)
        except Exception:
            return default

    def _to_int(self, raw: Optional[str], default: int = 0) -> int:
        return int(round(self._to_float(raw, default=float(default))))

    def _parse_device_datetime(
        self,
        received: Optional[str],
        controller_time: Optional[str],
        tz: ZoneInfo,
        fallback: datetime,
    ) -> datetime:
        """
        Best-effort:
          - if received (dd/mm/yyyy hh:mm) exists -> parse it
          - else if controller_time (hh:mm) exists -> use today's date with that time
        """
        if received:
            s = received.strip()
            # Example: "29/12/2025 16:37"
            for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S"):
                try:
                    dt = datetime.strptime(s, fmt).replace(tzinfo=tz)
                    return dt
                except Exception:
                    pass

        if controller_time:
            s = controller_time.strip()
            for fmt in ("%H:%M", "%H:%M:%S"):
                try:
                    t = datetime.strptime(s, fmt).time()
                    dt = datetime.now(tz).replace(hour=t.hour, minute=t.minute, second=t.second, microsecond=0)
                    return dt
                except Exception:
                    pass

        if fallback.tzinfo is None:
            return fallback.replace(tzinfo=tz)
        return fallback
