import json
from typing import Dict
import requests

class NhcApiError(RuntimeError):
    pass

def _pretty_body(resp: requests.Response) -> str:
    try:
        return json.dumps(resp.json(), ensure_ascii=False, indent=2)
    except Exception:
        return resp.text

def _raise_for_bad(resp: requests.Response) -> None:
    if 200 <= resp.status_code < 300:
        return
    raise NhcApiError(f"HTTP {resp.status_code} {resp.request.method} {resp.url}\n{_pretty_body(resp)}")

def _h(token: str) -> Dict[str, str]:
    return {"X-Auth-Token": token, "Content-Type": "application/json"}