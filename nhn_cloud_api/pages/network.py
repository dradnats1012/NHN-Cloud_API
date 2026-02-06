import json
import ipaddress
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

IDENTITY_BASE = "https://api-identity-infrastructure.nhncloudservice.com"
TOKEN_URI = "/v2.0/tokens"

DEFAULT_NETWORK_BASE = "https://kr1-api-network-infrastructure.nhncloudservice.com"
DEFAULT_COMPUTE_BASE = "https://kr1-api-instance-infrastructure.nhncloudservice.com"
DEFAULT_IMAGE_BASE = "https://kr1-api-image-infrastructure.nhncloudservice.com"


class NhcApiError(RuntimeError):
    pass


def _pretty_body(resp: requests.Response) -> str:
    try:
        body = resp.json()
        return json.dumps(body, ensure_ascii=False, indent=2)
    except Exception:
        return resp.text


def _raise_for_bad(resp: requests.Response) -> None:
    if 200 <= resp.status_code < 300:
        return
    raise NhcApiError(f"HTTP {resp.status_code} {resp.request.method} {resp.url}\n{_pretty_body(resp)}")


def _h(token: str) -> Dict[str, str]:
    return {"X-Auth-Token": token, "Content-Type": "application/json"}


def _validate_network_inputs(vpc_cidr: str, subnet_cidr: str, gateway: Optional[str]) -> None:
    vpc_net = ipaddress.ip_network(vpc_cidr, strict=False)
    subnet_net = ipaddress.ip_network(subnet_cidr, strict=False)

    if not subnet_net.subnet_of(vpc_net):
        raise ValueError(f"서브넷 CIDR({subnet_net})이 VPC CIDR({vpc_net}) 범위 밖입니다.")

    if gateway:
        gw_ip = ipaddress.ip_address(gateway)
        if gw_ip not in subnet_net:
            raise ValueError(f"Gateway({gw_ip})가 서브넷 CIDR({subnet_net}) 범위 밖입니다.")


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


def list_vpcs(network_base: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{network_base}/v2.0/vpcs", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("vpcs", [])


def list_subnets(network_base: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{network_base}/v2.0/vpcsubnets", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("vpcsubnets", [])


def list_security_groups(network_base: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{network_base}/v2.0/security-groups", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("security_groups", [])


def create_vpc(network_base: str, token: str, name: str, cidrv4: str) -> Dict[str, Any]:
    payload = {"vpc": {"name": name, "cidrv4": cidrv4}}
    r = requests.post(f"{network_base}/v2.0/vpcs", headers=_h(token), json=payload, timeout=30)
    _raise_for_bad(r)
    return r.json().get("vpc", r.json())


def create_subnet(network_base: str, token: str, vpc_id: str, name: str, cidr: str, gateway: Optional[str]) -> Dict[str, Any]:
    subnet_obj: Dict[str, Any] = {"name": name, "vpc_id": vpc_id, "cidr": cidr}
    if gateway:
        subnet_obj["gateway"] = gateway

    payload = {"vpcsubnet": subnet_obj}
    r = requests.post(f"{network_base}/v2.0/vpcsubnets", headers=_h(token), json=payload, timeout=30)
    _raise_for_bad(r)
    return r.json().get("vpcsubnet", r.json())


st.title("NHN Cloud: VPC/서브넷 생성 + 네트워크 리소스 조회")

st.session_state.setdefault("tenant_id", "")
st.session_state.setdefault("username", "")
st.session_state.setdefault("api_password", "")
st.session_state.setdefault("network_base", DEFAULT_NETWORK_BASE)
st.session_state.setdefault("compute_base", DEFAULT_COMPUTE_BASE)
st.session_state.setdefault("image_base", DEFAULT_IMAGE_BASE)
st.session_state.setdefault("token", None)

with st.form("auth"):
    st.subheader("인증")
    tenant_id = st.text_input("Tenant ID", value=st.session_state.tenant_id)
    username = st.text_input("Username", value=st.session_state.username)
    api_password = st.text_input("API Password", type="password", value=st.session_state.api_password)

    st.subheader("엔드포인트")
    network_base = st.text_input("Network Endpoint", value=st.session_state.network_base)

    submitted_auth = st.form_submit_button("토큰 발급")

if submitted_auth:
    try:
        if not tenant_id.strip() or not username.strip() or not api_password.strip():
            raise ValueError("Tenant ID / Username / API Password는 필수입니다.")

        st.session_state.tenant_id = tenant_id.strip()
        st.session_state.username = username.strip()
        st.session_state.api_password = api_password
        st.session_state.network_base = network_base.strip()

        st.session_state.token = issue_token(st.session_state.tenant_id, st.session_state.username, st.session_state.api_password)
        st.success("토큰 발급 성공")
    except Exception as e:
        st.error(str(e))

if not st.session_state.token:
    st.info("먼저 토큰을 발급하세요.")
    st.stop()
else:
    st.caption(f"현재 tenant_id: {st.session_state.tenant_id}")

st.divider()
st.subheader("0) VPC/서브넷 생성")

with st.form("create_network"):
    col1, col2 = st.columns(2)
    with col1:
        vpc_name = st.text_input("새 VPC Name", value="lab-vpc")
        vpc_cidr = st.text_input("새 VPC CIDR", value="10.10.0.0/20")
    with col2:
        create_subnet_too = st.checkbox("VPC 생성 후 서브넷도 같이 생성", value=True)
        subnet_name = st.text_input("새 Subnet Name", value="lab-subnet-a")
        subnet_cidr = st.text_input("새 Subnet CIDR", value="10.10.0.0/24")
        subnet_gw = st.text_input("Gateway (optional)", value="10.10.0.1")

    ok = st.form_submit_button("VPC/서브넷 생성")

if ok:
    try:
        if not vpc_name.strip() or not vpc_cidr.strip():
            raise ValueError("VPC Name / VPC CIDR는 필수입니다.")

        gw = subnet_gw.strip() if subnet_gw.strip() else None
        if create_subnet_too:
            if not subnet_name.strip() or not subnet_cidr.strip():
                raise ValueError("서브넷을 같이 만들려면 Subnet Name / Subnet CIDR가 필요합니다.")
            _validate_network_inputs(vpc_cidr.strip(), subnet_cidr.strip(), gw)

        vpc = create_vpc(st.session_state.network_base.strip(), st.session_state.token, vpc_name.strip(), vpc_cidr.strip())
        st.success(f"VPC 생성 완료: {vpc.get('name')} ({vpc.get('id')})")
        st.json(vpc)

        if create_subnet_too:
            subnet = create_subnet(
                st.session_state.network_base.strip(),
                st.session_state.token,
                str(vpc.get("id")),
                subnet_name.strip(),
                subnet_cidr.strip(),
                gw,
            )
            st.success(f"서브넷 생성 완료: {subnet.get('name')} ({subnet.get('id')})")
            st.json(subnet)

    except Exception as e:
        st.error(str(e))

st.divider()
st.subheader("1) 네트워크 리소스 조회")

if st.button("네트워크 리소스 불러오기 / 새로고침"):
    try:
        token = st.session_state.token
        vpcs = list_vpcs(st.session_state.network_base.strip(), token)
        subnets = list_subnets(st.session_state.network_base.strip(), token)
        sgs = list_security_groups(st.session_state.network_base.strip(), token)
        st.json(
            {
                "vpcs_count": len(vpcs),
                "subnets_count": len(subnets),
                "security_groups_count": len(sgs),
            }
        )
    except Exception as e:
        st.error(str(e))