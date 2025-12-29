import logging
import time
from enum import Enum, IntEnum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

try:
    from zoneinfo import ZoneInfo
except Exception:
    from backports.zoneinfo import ZoneInfo  # type: ignore

import requests

logger = logging.getLogger(__name__)

DEFAULT_API_BASE_URL = "https://api.myiquaapp.com/v1"
DEFAULT_USER_AGENT = "Mozilla/5.0 (HomeAssistant; iqua-softener) requests"

DEFAULT_TIMEOUT_SECONDS = 20
RETRY_MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.0


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
    # Kept for backward compatibility; integration can ignore this now.
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
    iQua Softener client for api.myiquaapp.com.

    Auth:
      POST /auth/login with JSON {email, password}
      -> access_token, refresh_token

    Data:
      GET /devices/{device_uuid}/debug
      -> DeviceDebugInfo (groups/items)

    Parsing:
      parse_debug(debug_json) -> {"kv": {...}, "tables": {...}}
    """

    def __init__(
        self,
        username: str,
        password: str,
        device_uuid: str,
        api_base_url: str = DEFAULT_API_BASE_URL,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        # username is email
        self._email: str = username
        self._password: str = password
        self._device_uuid: str = device_uuid

        self._api_base_url: str = api_base_url.rstrip("/")
        self._user_agent: str = user_agent

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None

    @property
    def device_uuid(self) -> str:
        return self._device_uuid

    # Backwards-compatible alias
    @property
    def device_serial_number(self) -> str:
        return self._device_uuid

    # ----------------------------
    # Public API
    # ----------------------------

    def get_debug(self) -> dict:
        """
        Fetch /devices/{uuid}/debug JSON.
        """
        with requests.Session() as session:
            self._ensure_login(session)

            url = self._get_url(f"devices/{self._device_uuid}/debug")
            data = self._authorized_get_json(session, url)
            if not isinstance(data, dict):
                raise IquaSoftenerException("Unexpected debug payload type.")
            return data

    @staticmethod
    def parse_debug(debug_json: dict) -> dict:
        """
        Parse debug JSON into flat kv + tables structure.

        Returns:
        {
          "kv": {key: value},
          "tables": {table_key: {column_titles, rows}}
        }
        """
        kv: Dict[str, Any] = {}
        tables: Dict[str, Any] = {}

        groups = debug_json.get("groups", [])
        if not isinstance(groups, list):
            return {"kv": kv, "tables": tables}

        for group in groups:
            if not isinstance(group, dict):
                continue
            items = group.get("items", [])
            if not isinstance(items, list):
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue

                item_type = item.get("type")
                key = item.get("key")
                if not isinstance(key, str):
                    continue

                if item_type == "kv":
                    item_kv = item.get("item_kv", {})
                    if isinstance(item_kv, dict) and "value" in item_kv:
                        kv[key] = item_kv.get("value")

                elif item_type == "table":
                    item_table = item.get("item_table", {})
                    if isinstance(item_table, dict):
                        tables[key] = {
                            "column_titles": item_table.get("column_titles", []),
                            "rows": item_table.get("rows", []),
                        }

        return {"kv": kv, "tables": tables}

    # Optional compatibility method: return parsed debug directly
    def get_parsed(self) -> dict:
        debug = self.get_debug()
        return self.parse_debug(debug)

    # ----------------------------
    # Auth + HTTP
    # ----------------------------

    def _ensure_login(self, session: requests.Session) -> None:
        if self._access_token is None:
            self._login(session)

    def _login(self, session: requests.Session) -> None:
        url = self._get_url("auth/login")
        payload = {"email": self._email, "password": self._password}

        resp = self._request_with_retries(
            session=session,
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
        self._access_token = str(access)
        self._refresh_token = str(refresh) if refresh is not None else None

    def _authorized_get_json(self, session: requests.Session, url: str) -> Any:
        headers = self._get_headers(with_auth=True)
        resp = self._request_with_retries(session, "GET", url, headers=headers)

        if resp.status_code == 401:
            # token expired/invalid: relogin once
            self._access_token = None
            self._login(session)
            headers = self._get_headers(with_auth=True)
            resp = self._request_with_retries(session, "GET", url, headers=headers)

        if resp.status_code != 200:
            raise IquaSoftenerException(f"Invalid status ({resp.status_code}) for data request: {url}")

        return resp.json()

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

                if resp.status_code in (429, 502, 503, 504):
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

    def _get_url(self, resource: str) -> str:
        return f"{self._api_base_url}/{resource.lstrip('/')}"

    def _get_headers(self, with_auth: bool = True) -> Dict[str, str]:
        headers = {
            "User-Agent": self._user_agent,
            "Accept": "application/json",
        }
        if with_auth and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        return headers