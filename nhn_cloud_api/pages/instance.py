# nhncloud_network_ui.py
import json
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

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
    raise NhcApiError(
        f"HTTP {resp.status_code} {resp.request.method} {resp.url}\n{_pretty_body(resp)}"
    )


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
    # OpenStack Neutron compatible path
    r = requests.get(f"{network_base}/v2.0/security-groups", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("security_groups", [])



def list_images(image_base: str, token: str) -> List[Dict[str, Any]]:
    # Image API (Glance): GET /v2/images
    r = requests.get(f"{image_base}/v2/images", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("images", [])


def list_flavors(compute_base: str, token: str, tenant_id: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{compute_base}/v2/{tenant_id}/flavors/detail", headers=_h(token), timeout=30)
    if r.status_code == 404:
        # some setups only provide /flavors
        r = requests.get(f"{compute_base}/v2/{tenant_id}/flavors", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    return r.json().get("flavors", [])


def list_keypairs(compute_base: str, token: str, tenant_id: str) -> List[Dict[str, Any]]:
    r = requests.get(f"{compute_base}/v2/{tenant_id}/os-keypairs", headers=_h(token), timeout=30)
    _raise_for_bad(r)
    keypairs = r.json().get("keypairs", [])

    out = []
    for item in keypairs:
        kp = item.get("keypair", item)
        out.append(kp)
    return out


def create_keypair(
    compute_base: str,
    token: str,
    tenant_id: str,
    name: str,
    public_key: Optional[str] = None,
) -> Dict[str, Any]:
    
    payload: Dict[str, Any] = {"keypair": {"name": name}}
    if public_key and public_key.strip():
        payload["keypair"]["public_key"] = public_key.strip()

    r = requests.post(
        f"{compute_base}/v2/{tenant_id}/os-keypairs",
        headers=_h(token),
        json=payload,
        timeout=30,
    )
    _raise_for_bad(r)
    return r.json().get("keypair", r.json())


def create_instance(
    compute_base: str,
    token: str,
    tenant_id: str,
    name: str,
    image_id: str,
    flavor_id: str,
    subnet_id: str,
    key_name: Optional[str],
    sg_names: List[str],
    availability_zone: Optional[str] = None,
    root_volume_size: int = 20,
) -> Dict[str, Any]:
    url = f"{compute_base}/v2/{tenant_id}/servers"

    server: Dict[str, Any] = {
        "name": name,
        "imageRef": image_id,
        "flavorRef": flavor_id,
        "networks": [{"subnet": subnet_id}],
        "security_groups": [{"name": n} for n in sg_names] if sg_names else [],
        "min_count": 1,
        "max_count": 1,
        "block_device_mapping_v2": [
            {
                "source_type": "image",
                "uuid": image_id,
                "boot_index": 0,
                "destination_type": "volume",
                "volume_size": int(root_volume_size),
                "delete_on_termination": 1,
            }
        ],
    }

    if key_name:
        server["key_name"] = key_name

    if availability_zone:
        server["availability_zone"] = availability_zone

    payload = {"server": server}

    r = requests.post(url, headers=_h(token), json=payload, timeout=60)
    _raise_for_bad(r)
    return r.json().get("server", r.json())


st.title("NHN Cloud: 기존 리소스 선택 → 인스턴스 생성")

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
    compute_base = st.text_input("Instance Endpoint", value=st.session_state.compute_base)
    image_base = st.text_input("Image Endpoint", value=st.session_state.image_base)

    submitted_auth = st.form_submit_button("토큰 발급")

if submitted_auth:
    try:
        if not tenant_id.strip() or not username.strip() or not api_password.strip():
            raise ValueError("Tenant ID / Username / API Password는 필수입니다.")

        st.session_state.tenant_id = tenant_id.strip()
        st.session_state.username = username.strip()
        st.session_state.api_password = api_password
        st.session_state.network_base = network_base.strip()
        st.session_state.compute_base = compute_base.strip()
        st.session_state.image_base = image_base.strip()

        st.session_state.token = issue_token(st.session_state.tenant_id, st.session_state.username, st.session_state.api_password)
        st.success("토큰 발급 성공")
    except NhcApiError as e:
        st.error("토큰 발급 실패")
        st.code(str(e))
    except Exception as e:
        st.error(f"실패: {e}")

if not st.session_state.token:
    st.info("먼저 토큰을 발급하세요.")
    st.stop()
else:
    st.caption(f"현재 tenant_id: {st.session_state.tenant_id}")

st.divider()

st.subheader("1) 기존 리소스 불러오기")

col1, col2 = st.columns(2)
with col1:
    refresh = st.button("리소스 불러오기 / 새로고침")
with col2:
    st.caption("VPC/서브넷/보안그룹/이미지/플레이버/키페어 목록을 API로 조회합니다.")

if refresh or "resources" not in st.session_state:
    try:
        token = st.session_state.token
        resources = {
            "vpcs": list_vpcs(st.session_state.network_base.strip(), token),
            "subnets": list_subnets(st.session_state.network_base.strip(), token),
            "security_groups": list_security_groups(st.session_state.network_base.strip(), token),
            "images": list_images(st.session_state.image_base.strip(), token),
            "flavors": list_flavors(st.session_state.compute_base.strip(), token, st.session_state.tenant_id.strip()),
            "keypairs": list_keypairs(st.session_state.compute_base.strip(), token, st.session_state.tenant_id.strip()),
        }
        st.session_state.resources = resources
        st.success(
            f"불러오기 완료: vpc={len(resources['vpcs'])}, subnet={len(resources['subnets'])}, sg={len(resources['security_groups'])}, image={len(resources['images'])}, flavor={len(resources['flavors'])}, keypair={len(resources['keypairs'])}"
        )
    except NhcApiError as e:
        st.error("리소스 조회 실패")
        st.code(str(e))
        st.stop()

resources = st.session_state.resources
st.divider()
st.subheader("1.5) 키페어 (없으면 생성)")

keypairs_count = len(resources.get("keypairs", []))
if keypairs_count == 0:
    st.warning("현재 Keypair가 0개입니다. 인스턴스 SSH 접속을 위해 키페어 생성/등록을 권장합니다.")

with st.expander("키페어 생성/등록", expanded=(keypairs_count == 0)):
    st.caption(
        "- NHN 키페어 API는 '생성 요청 응답'에 private_key가 포함될 때만 PEM을 받을 수 있습니다. "
        "(대부분 1회만 제공, 이후 재다운로드 API 없음)\n"
        "- 만약 새 키페어 생성인데도 private_key가 안 내려오면, 이 환경은 서버 생성형 키페어(private key 반환)가 비활성화된 구성일 수 있습니다.\n"
        "  → 이 경우 로컬에서 키를 만든 뒤(public/private), public_key만 등록해서 사용하세요."
    )

    with st.form("create_keypair_form"):
        kp_name = st.text_input("Keypair Name", value="lab-keypair-1")
        mode = st.radio("방식", ["새 키페어 생성(추천)", "기존 공개키 등록"], horizontal=True)

        public_key = ""
        if mode == "기존 공개키 등록":
            uploaded_pub = st.file_uploader("Public key 파일 업로드 (.pub)", type=["pub"], accept_multiple_files=False)
            if uploaded_pub is not None:
                try:
                    public_key = uploaded_pub.getvalue().decode("utf-8").strip()
                except Exception:
                    public_key = ""

            public_key = st.text_area(
                "Public Key",
                value=public_key,
                placeholder="ssh-rsa AAAA... user@host",
                height=120,
                help="로컬에 이미 있는 키페어를 쓰려면: (1) .pub 파일을 업로드하거나 (2) 내용을 붙여넣기 하면 됩니다.",
            )

            st.info(
                "로컬에 .pem(개인키)만 있고 .pub(공개키)가 없다면 터미널에서 공개키를 뽑을 수 있어요:\n"
                "  ssh-keygen -y -f <private_key.pem> > <private_key>.pub\n"
                "그 다음 생성/등록 화면에서 .pub를 업로드/붙여넣기 하세요."
            )
        submitted_kp = st.form_submit_button("키페어 만들기/등록")

    if submitted_kp:
        try:
            if not kp_name.strip():
                raise ValueError("Keypair Name은 필수입니다.")

            kp = create_keypair(
                compute_base=st.session_state.compute_base.strip(),
                token=st.session_state.token,
                tenant_id=st.session_state.tenant_id.strip(),
                name=kp_name.strip(),
                public_key=public_key if mode == "기존 공개키 등록" else None,
            )
            st.success(f"키페어 완료: {kp.get('name')}")
            with st.expander("키페어 API 응답(디버그)", expanded=False):
                st.json(kp)

            # private_key는 '새 키페어 생성'일 때만 내려오는 경우가 많고,
            # 환경/설정(API microversion 등)에 따라 아예 내려오지 않을 수 있음.
            priv = kp.get("private_key")
            if priv:
                st.warning("⚠️ Private Key는 보통 재조회가 불가합니다. 지금 바로 저장하세요.")
                st.code(priv, language="text")
                st.download_button(
                    "private key 다운로드 (.pem)",
                    data=priv,
                    file_name=f"{kp_name.strip()}.pem",
                    mime="application/x-pem-file",
                )
            else:
                st.warning(
                    "이 응답에는 private_key가 없습니다. 이 환경에서는 API로 '서버 생성형 키페어(PEM 반환)'가 비활성화되어 있을 수 있어요.\n"
                    "→ 로컬에서 키를 생성한 뒤(.pem/.pub) public_key만 '기존 공개키 등록'으로 등록해서 사용하세요.\n"
                    "(키페어 생성 자체는 인스턴스 생성 시 public_key 주입을 위해 여전히 의미가 있습니다.)"
                )

            # 생성 후 keypairs 목록 갱신 -> 드롭다운에 바로 반영
            resources["keypairs"] = list_keypairs(
                st.session_state.compute_base.strip(),
                st.session_state.token,
                st.session_state.tenant_id.strip(),
            )
            st.session_state.resources = resources
            st.rerun()

        except NhcApiError as e:
            st.error("키페어 생성/등록 실패 (API 4xx/5xx)")
            st.code(str(e))
        except Exception as e:
            st.error(f"실패: {e}")
            
with st.expander("조회 결과 미리보기(디버그)"):
    st.json(
        {
            "vpcs_count": len(resources.get("vpcs", [])),
            "subnets_count": len(resources.get("subnets", [])),
            "security_groups_count": len(resources.get("security_groups", [])),
            "images_count": len(resources.get("images", [])),
            "flavors_count": len(resources.get("flavors", [])),
            "keypairs_count": len(resources.get("keypairs", [])),
        }
    )

st.divider()

st.subheader("2) 인스턴스 생성 입력")


def _opt(items: List[Dict[str, Any]], label_fn) -> Tuple[List[str], Dict[str, Dict[str, Any]]]:
    mapping: Dict[str, Dict[str, Any]] = {}
    labels: List[str] = []
    for it in items:
        label = label_fn(it)
        labels.append(label)
        mapping[label] = it
    labels.sort()
    return labels, mapping


vpc_labels, vpc_map = _opt(
    resources.get("vpcs", []),
    lambda v: f"{v.get('name','')} ({v.get('id','')})"
)
subnet_labels, subnet_map = _opt(
    resources.get("subnets", []),
    lambda s: f"{s.get('name','')} ({s.get('id','')}) | {s.get('cidr','')}"
)
image_labels, image_map = _opt(
    resources.get("images", []),
    lambda im: (
        f"{im.get('name','')} ({im.get('id','')})"
        f" | min_ram={im.get('min_ram',0)}MB, min_disk={im.get('min_disk',0)}GB"
    )
)

keypair_labels, keypair_map = _opt(
    resources.get("keypairs", []),
    lambda kp: f"{kp.get('name','')} ({kp.get('name','')})"
)

sg_items = resources.get("security_groups", [])
sg_names = sorted([str(sg.get("name")) for sg in sg_items if sg.get("name")])

colA, colB = st.columns(2)
with colA:
    instance_name = st.text_input("Instance Name", value="lab-instance-1")

    show_all_subnets = st.checkbox(
        "서브넷 전체 보기(테넌트 전체) — 체크 해제 시 선택한 VPC의 서브넷만 표시",
        value=False,
    )

    selected_vpc = st.selectbox(
        "VPC",
        options=vpc_labels or ["(없음)"],
        disabled=not bool(vpc_labels),
    )

    all_subnets = resources.get("subnets", [])
    filtered_subnets = all_subnets

    selected_vpc_id = None
    if vpc_labels and selected_vpc in vpc_map:
        selected_vpc_id = vpc_map[selected_vpc].get("id")

    if (not show_all_subnets) and selected_vpc_id:
        filtered_subnets = [s for s in all_subnets if str(s.get("vpc_id")) == str(selected_vpc_id)]

    subnet_labels, subnet_map = _opt(
        filtered_subnets,
        lambda s: f"{s.get('name','')} ({s.get('id','')}) | {s.get('cidr','')}"
    )

    selected_subnet = st.selectbox(
        "Subnet",
        options=subnet_labels or ["(없음)"],
        disabled=not bool(subnet_labels),
        help=(
            f"표시 중: {len(filtered_subnets)}개 / 전체: {len(all_subnets)}개"
            + (f" (VPC: {selected_vpc_id})" if selected_vpc_id else "")
        ),
    )

with colB:
    selected_image = st.selectbox(
        "Image",
        options=image_labels or ["(없음)"],
        disabled=not bool(image_labels),
    )

    filter_flavors = st.checkbox(
        "이미지 요구사항을 만족하는 Flavor만 보기",
        value=True,
        help="에러: Flavor's memory is too small... 를 예방하기 위한 필터입니다.",
    )

    required_min_ram = 0
    required_min_disk = 0
    if selected_image != "(없음)" and selected_image in image_map:
        _im = image_map[selected_image]
        required_min_ram = int(_im.get("min_ram", 0) or 0)
        required_min_disk = int(_im.get("min_disk", 0) or 0)

    all_flavors = resources.get("flavors", [])
    filtered_flavors = all_flavors
    if filter_flavors:
        filtered_flavors = [
            f for f in all_flavors
            if int(f.get("ram", 0) or 0) >= required_min_ram
            and int(f.get("disk", 0) or 0) >= required_min_disk
        ]

    flavor_labels, flavor_map = _opt(
        filtered_flavors,
        lambda fv: (
            f"{fv.get('name','')} ({fv.get('id','')})"
            f" | ram={fv.get('ram',0)}MB, vcpus={fv.get('vcpus',0)}, disk={fv.get('disk',0)}GB"
        )
    )

    if filter_flavors:
        st.caption(
            f"선택한 이미지 요구사항: min_ram={required_min_ram}MB, min_disk={required_min_disk}GB | "
            f"표시 중 flavor: {len(filtered_flavors)}개 / 전체: {len(all_flavors)}개"
        )

    selected_flavor = st.selectbox(
        "Flavor",
        options=flavor_labels or ["(없음)"],
        disabled=not bool(flavor_labels),
    )

    selected_keypair = st.selectbox(
        "Keypair (optional)",
        options=["(없음)"] + (keypair_labels or []),
    )

selected_sgs = st.multiselect(
    "Security Groups (name 기반)",
    options=sg_names,
    default=["default"] if "default" in sg_names else (sg_names[:1] if sg_names else []),
)

availability_zone = st.text_input("Availability Zone (optional)", value="")

root_volume_size = st.number_input(
    "Root Volume Size (GB)",
    min_value=1,
    max_value=2000,
    value=20,
    step=1,
    help="에러가 'Missing Block Device Mapping attribute'로 뜨면 이 값이 포함되어야 합니다.",
)

create_btn = st.button("인스턴스 생성")

if create_btn:
    try:
        if not instance_name.strip():
            raise ValueError("Instance Name은 필수입니다.")
        if not subnet_labels:
            raise ValueError("Subnet 목록이 없습니다. 먼저 '리소스 불러오기'를 눌러주세요.")
        if not image_labels:
            raise ValueError("Image 목록이 없습니다.")
        if not flavor_labels:
            raise ValueError("Flavor 목록이 없습니다.")

        if selected_image == "(없음)" or selected_image not in image_map:
            raise ValueError("유효한 Image를 선택하세요.")
        if selected_flavor == "(없음)" or selected_flavor not in flavor_map:
            raise ValueError("유효한 Flavor를 선택하세요. (이미지 요구사항 필터를 켜보세요)")
        if selected_subnet == "(없음)" or selected_subnet not in subnet_map:
            raise ValueError("유효한 Subnet을 선택하세요.")

        subnet = subnet_map[selected_subnet]
        image = image_map[selected_image]
        flavor = flavor_map[selected_flavor]

        # 추가 사전검증: Flavor RAM < Image min_ram이면 API가 400을 반환함
        min_ram = int(image.get("min_ram", 0) or 0)
        if int(flavor.get("ram", 0) or 0) < min_ram:
            raise ValueError(
                f"선택한 Flavor RAM({flavor.get('ram',0)}MB)이 이미지 최소 RAM({min_ram}MB)보다 작습니다. 더 큰 Flavor를 선택하세요."
            )

        kp_name: Optional[str] = None
        if selected_keypair != "(없음)":
            kp_name = keypair_map[selected_keypair].get("name") or keypair_map[selected_keypair].get("keypair", {}).get("name")

        server = create_instance(
            compute_base=st.session_state.compute_base.strip(),
            token=st.session_state.token,
            tenant_id=st.session_state.tenant_id.strip(),
            name=instance_name.strip(),
            image_id=str(image.get("id")),
            flavor_id=str(flavor.get("id")),
            subnet_id=str(subnet.get("id")),
            key_name=kp_name,
            sg_names=list(selected_sgs),
            availability_zone=availability_zone.strip() or None,
            root_volume_size=int(root_volume_size),
        )

        st.success("인스턴스 생성 요청 성공")
        st.write("### 응답")
        st.json(server)

        # Common: server id in response
        sid = server.get("id")
        if sid:
            st.info(f"server_id: {sid}")

    except NhcApiError as e:
        st.error("인스턴스 생성 실패 (API 4xx/5xx)")
        st.code(str(e))
    except Exception as e:
        st.error(f"실패: {e}")