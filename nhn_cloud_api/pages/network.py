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


def list_routingtables(network_base: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{network_base}/v2.0/routingtables", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("routingtables", [])


def create_routingtable(network_base: str, token: str, name: str, vpc_id: str) -> Dict[str, Any]:
    payload = {"routingtable": {"name": name, "vpc_id": vpc_id}}
    r = requests.post(f"{network_base}/v2.0/routingtables", headers=_h(token), json=payload, timeout=30)
    _raise_for_bad(r)
    return r.json().get("routingtable", r.json())


def list_internetgateways(network_base: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{network_base}/v2.0/internetgateways", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("internetgateways", [])


def create_internetgateway(network_base: str, token: str, name: str, external_network_id: str) -> Dict[str, Any]:
    payload = {"internetgateway": {"name": name, "external_network_id": external_network_id}}
    r = requests.post(f"{network_base}/v2.0/internetgateways", headers=_h(token), json=payload, timeout=30)
    _raise_for_bad(r)
    return r.json().get("internetgateway", r.json())


def attach_gateway_to_routingtable(network_base: str, token: str, routingtable_id: str, gateway_id: str) -> Dict[str, Any]:
    payload = {"gateway_id": gateway_id}
    r = requests.put(f"{network_base}/v2.0/routingtables/{routingtable_id}/attach_gateway", headers=_h(token), json=payload, timeout=30)
    _raise_for_bad(r)
    return r.json().get("routingtable", r.json())


def attach_subnet_to_routingtable(network_base: str, token: str, subnet_id: str, routingtable_id: str) -> Dict[str, Any]:
    payload = {"routingtable_id": routingtable_id}
    r = requests.put(f"{network_base}/v2.0/vpcsubnets/{subnet_id}/attach_routingtable", headers=_h(token), json=payload, timeout=30)
    _raise_for_bad(r)
    return r.json().get("vpcsubnet", r.json())


def list_external_networks(network_base: str, token: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{network_base}/v2.0/networks", headers=_h(token), params={"router:external": True}, timeout=30)
    _raise_for_bad(r)
    return r.json().get("networks", [])


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
st.subheader("1) 인터넷 게이트웨이 연결")
st.caption("VPC의 서브넷에 인터넷 연결을 설정합니다: 라우팅 테이블 생성 → 인터넷 게이트웨이 생성 → 연결")

_nb = st.session_state.network_base.strip()
_tk = st.session_state.token

if st.button("리소스 불러오기 (VPC/서브넷/라우팅테이블/IGW)"):
    try:
        st.session_state.net_vpcs = list_vpcs(_nb, _tk)
        st.session_state.net_subnets = list_subnets(_nb, _tk)
        st.session_state.net_rts = list_routingtables(_nb, _tk)
        st.session_state.net_igws = list_internetgateways(_nb, _tk)
        try:
            st.session_state.net_ext_nets = list_external_networks(_nb, _tk)
        except Exception:
            st.session_state.net_ext_nets = []
        st.success("불러오기 완료")
    except Exception as e:
        st.error(str(e))

if "net_vpcs" not in st.session_state:
    st.info("먼저 '리소스 불러오기' 버튼을 눌러주세요.")
else:
    vpcs = st.session_state.net_vpcs
    subnets = st.session_state.net_subnets
    rts = st.session_state.net_rts
    igws = st.session_state.net_igws
    ext_nets = st.session_state.get("net_ext_nets", [])

    with st.expander("현재 리소스 현황", expanded=False):
        st.json({
            "vpcs": len(vpcs),
            "subnets": len(subnets),
            "routing_tables": len(rts),
            "internet_gateways": len(igws),
            "external_networks": len(ext_nets),
        })

    vpc_opts = {f"{v.get('name','')} ({v.get('id','')})": v for v in vpcs}
    igw_opts = {f"{g.get('name','')} ({g.get('id','')})": g for g in igws}
    ext_net_opts = {f"{n.get('name','')} ({n.get('id','')})": n for n in ext_nets}

    # VPC 선택 (폼 밖에서 — 서브넷/라우팅테이블 필터링용)
    sel_vpc_label = st.selectbox("VPC 선택", options=list(vpc_opts.keys()) or ["(없음)"])
    sel_vpc_id = vpc_opts[sel_vpc_label].get("id") if sel_vpc_label in vpc_opts else None

    # 선택한 VPC에 속하는 서브넷/라우팅테이블만 필터링
    filtered_subnets = [s for s in subnets if str(s.get("vpc_id")) == str(sel_vpc_id)] if sel_vpc_id else subnets
    filtered_rts = [r for r in rts if str(r.get("vpc_id")) == str(sel_vpc_id)] if sel_vpc_id else rts

    subnet_opts = {f"{s.get('name','')} ({s.get('id','')}) | {s.get('cidr','')}": s for s in filtered_subnets}
    rt_opts = {f"{r.get('name','')} ({r.get('id','')})": r for r in filtered_rts}

    st.caption(f"선택한 VPC의 서브넷: {len(filtered_subnets)}개, 라우팅 테이블: {len(filtered_rts)}개")

    with st.form("igw_setup"):
        st.markdown("**1단계: 라우팅 테이블**")
        rt_mode = st.radio("라우팅 테이블", ["새로 생성", "기존 선택"], horizontal=True)

        if rt_mode == "새로 생성":
            rt_name = st.text_input("라우팅 테이블 이름", value="lab-rt")
        else:
            sel_existing_rt = st.selectbox("기존 라우팅 테이블", options=list(rt_opts.keys()) or ["(없음)"])

        st.markdown("**2단계: 인터넷 게이트웨이**")
        igw_mode = st.radio("인터넷 게이트웨이", ["새로 생성", "기존 선택"], horizontal=True)

        if igw_mode == "새로 생성":
            igw_name = st.text_input("인터넷 게이트웨이 이름", value="lab-igw")
            if ext_net_opts:
                sel_ext_net = st.selectbox("외부 네트워크", options=list(ext_net_opts.keys()))
            else:
                ext_net_id_manual = st.text_input(
                    "외부 네트워크 ID (직접 입력)",
                    help="외부 네트워크 조회가 안 될 경우 콘솔에서 확인 후 입력하세요.",
                )
        else:
            sel_existing_igw = st.selectbox("기존 인터넷 게이트웨이", options=list(igw_opts.keys()) or ["(없음)"])

        st.markdown("**3단계: 서브넷 연결**")
        sel_subnet_for_rt = st.selectbox("라우팅 테이블에 연결할 서브넷", options=list(subnet_opts.keys()) or ["(없음)"])

        submitted_igw = st.form_submit_button("인터넷 게이트웨이 설정 실행")

    if submitted_igw:
        try:
            if not sel_vpc_id:
                raise ValueError("VPC를 선택하세요.")

            # 1) 라우팅 테이블
            if rt_mode == "새로 생성":
                if not rt_name.strip():
                    raise ValueError("라우팅 테이블 이름을 입력하세요.")
                rt = create_routingtable(_nb, _tk, rt_name.strip(), sel_vpc_id)
                rt_id = rt.get("id")
                st.success(f"라우팅 테이블 생성 완료: {rt.get('name')} ({rt_id})")
            else:
                if sel_existing_rt == "(없음)":
                    raise ValueError("라우팅 테이블을 선택하세요.")
                rt_id = rt_opts[sel_existing_rt].get("id")
                st.info(f"기존 라우팅 테이블 사용: {rt_id}")

            # 2) 인터넷 게이트웨이
            if igw_mode == "새로 생성":
                if not igw_name.strip():
                    raise ValueError("인터넷 게이트웨이 이름을 입력하세요.")
                if ext_net_opts:
                    ext_id = ext_net_opts[sel_ext_net].get("id")
                else:
                    ext_id = ext_net_id_manual.strip()
                    if not ext_id:
                        raise ValueError("외부 네트워크 ID를 입력하세요.")
                igw = create_internetgateway(_nb, _tk, igw_name.strip(), ext_id)
                igw_id = igw.get("id")
                st.success(f"인터넷 게이트웨이 생성 완료: {igw.get('name')} ({igw_id})")
            else:
                if sel_existing_igw == "(없음)":
                    raise ValueError("인터넷 게이트웨이를 선택하세요.")
                igw_id = igw_opts[sel_existing_igw].get("id")
                st.info(f"기존 인터넷 게이트웨이 사용: {igw_id}")

            # 3) 라우팅 테이블에 IGW 연결
            result_rt = attach_gateway_to_routingtable(_nb, _tk, rt_id, igw_id)
            st.success(f"라우팅 테이블에 인터넷 게이트웨이 연결 완료 (gateway_id: {result_rt.get('gateway_id')})")

            # 4) 서브넷을 라우팅 테이블에 연결
            if sel_subnet_for_rt != "(없음)":
                subnet_id = subnet_opts[sel_subnet_for_rt].get("id")
                result_sn = attach_subnet_to_routingtable(_nb, _tk, subnet_id, rt_id)
                st.success(f"서브넷 → 라우팅 테이블 연결 완료: {result_sn.get('name')}")

            st.success("인터넷 게이트웨이 설정이 모두 완료되었습니다.")

        except NhcApiError as e:
            st.error("API 호출 실패")
            st.code(str(e))
        except Exception as e:
            st.error(f"실패: {e}")

st.divider()
st.subheader("2) 네트워크 리소스 조회")

if st.button("네트워크 리소스 불러오기 / 새로고침"):
    try:
        token = st.session_state.token
        vpcs = list_vpcs(_nb, token)
        subnets = list_subnets(_nb, token)
        sgs = list_security_groups(_nb, token)
        rts = list_routingtables(_nb, token)
        igws = list_internetgateways(_nb, token)
        st.json(
            {
                "vpcs_count": len(vpcs),
                "subnets_count": len(subnets),
                "security_groups_count": len(sgs),
                "routing_tables_count": len(rts),
                "internet_gateways_count": len(igws),
            }
        )
    except Exception as e:
        st.error(str(e))