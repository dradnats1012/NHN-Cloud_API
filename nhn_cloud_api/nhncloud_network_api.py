# nhncloud의 내가 가진 
# 네트워크 구성 조건문 받아서 API 돌려서 자동화 -> VPC, 서브넷, 라우팅테이블 등 

import requests
from typing import Any, Dict, Optional

IDENTITY_BASE = "https://api-identity-infrastructure.nhncloudservice.com"
TOKEN_URI = "/v2.0/tokens"


class NhcApiError(RuntimeError):
    """NHN Cloud API 호출 실패(상태코드, 응답바디 포함)"""


def _raise_for_bad(resp: requests.Response) -> None:
    if 200 <= resp.status_code < 300:
        return

    try:
        body = resp.json()
    except Exception:
        body = resp.text

    raise NhcApiError(
        f"HTTP {resp.status_code} {resp.request.method} {resp.url}\n"
        f"Response: {body}"
    )


def _headers(token: str) -> Dict[str, str]:
    return {"X-Auth-Token": token, "Content-Type": "application/json"}


def issue_token(tenant_id: str, username: str, api_password: str) -> str:
    body = {
        "auth": {
            "tenantId": tenant_id,
            "passwordCredentials": {"username": username, "password": api_password},
        }
    }
    r = requests.post(IDENTITY_BASE + TOKEN_URI, json=body, timeout=20)
    _raise_for_bad(r)
    return r.json()["access"]["token"]["id"]


def create_vpc(network_base: str, token: str, name: str, cidrv4: str) -> Dict[str, Any]:
    payload = {"vpc": {"name": name, "cidrv4": cidrv4}}
    r = requests.post(
        f"{network_base}/v2.0/vpcs",
        headers=_headers(token),
        json=payload,
        timeout=30,
    )
    _raise_for_bad(r)
    return r.json()["vpc"]


def create_subnet(
    network_base: str,
    token: str,
    vpc_id: str,
    name: str,
    cidr: str,
    gateway: Optional[str],
    enable_dhcp: Optional[bool] = None,
) -> Dict[str, Any]:
    #Create a VPC subnet.


    subnet_obj: Dict[str, Any] = {
        "name": name,
        "vpc_id": vpc_id,
        "cidr": cidr,
    }

    # NOTE: In responses the field name is `gateway` (not gateway_ip).
    if gateway:
        subnet_obj["gateway"] = gateway

    # Some environments allow/return enable_dhcp; include only if explicitly set.
    if enable_dhcp is not None:
        subnet_obj["enable_dhcp"] = enable_dhcp

    payload = {"vpcsubnet": subnet_obj}

    r = requests.post(
        f"{network_base}/v2.0/vpcsubnets",
        headers=_headers(token),
        json=payload,
        timeout=30,
    )
    _raise_for_bad(r)
    return r.json()["vpcsubnet"]


def create_keypair(
    compute_base: str,
    token: str,
    tenant_id: str,
    name: str,
    public_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    POST /v2/{tenantId}/os-keypairs
    - public_key 비우면 새 키페어 생성
    - public_key 주면 기존 공개키 등록
    """
    payload: Dict[str, Any] = {"keypair": {"name": name}}
    if public_key and public_key.strip():
        payload["keypair"]["public_key"] = public_key.strip()

    r = requests.post(
        f"{compute_base}/v2/{tenant_id}/os-keypairs",
        headers=_headers(token),
        json=payload,
        timeout=30,
    )
    _raise_for_bad(r)

    # 응답은 보통 {"keypair": {...}} 형태
    return r.json().get("keypair", r.json())