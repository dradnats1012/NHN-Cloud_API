# NHN Cloud Infrastructure Provisioning Tool

NHN Cloud API를 활용한 클라우드 인프라 자동 프로비저닝 웹 도구입니다.
Streamlit 기반 UI를 통해 VPC, 서브넷, 인터넷 게이트웨이, 인스턴스, 플로팅 IP까지 한 번에 구성할 수 있습니다.

## 주요 기능

- **토큰 인증** — NHN Cloud Identity API를 통한 인증 토큰 발급
- **VPC / 서브넷 생성** — CIDR 유효성 검증 포함
- **인터넷 게이트웨이 연결** — 라우팅 테이블 생성 → IGW 생성 → 서브넷 연결까지 자동화
- **인스턴스 생성** — 이미지, 플레이버, 서브넷, 보안그룹, 키페어를 선택하여 생성
- **플로팅 IP 연결** — 인스턴스에 공인 IP를 할당하여 외부 접속 가능
- **키페어 관리** — 새 키페어 생성 또는 기존 공개키 등록 (PEM 다운로드 지원)
- **스마트 필터링** — 이미지 최소 요구사항(RAM, Disk)에 맞는 플레이버만 표시

## 프로젝트 구조

```
├── requirements.txt
├── user_data.sh              # 인스턴스 사용자 스크립트 (Ubuntu, cloud-init)
└── nhn_cloud_api/
    ├── main.py               # Streamlit 앱 엔트리포인트 (홈 페이지)
    ├── nhncloud_common.py    # 공통 유틸 (에러 처리, 헤더 생성)
    ├── nhncloud_token.py     # 토큰 발급 스크립트
    ├── nhncloud_network_api.py   # 네트워크 API 함수
    ├── nhncloud_network_ui.py    # 인스턴스 생성 UI + API (통합 모듈)
    └── pages/
        ├── Network.py        # VPC/서브넷 생성, 인터넷 게이트웨이 연결, 리소스 조회
        └── Instance.py       # 인스턴스 생성, 키페어 관리, 플로팅 IP 연결
```

## Quick Start

### 1. 클론 및 의존성 설치

```bash
git clone https://github.com/dradnats1012/NHN-Cloud_API.git
cd NHN-Cloud_API
pip install -r requirements.txt
streamlit run nhn_cloud_api/main.py
```

## 사용 흐름

1. **토큰 발급** — Tenant ID, Username, API Password를 입력하여 인증 토큰 발급
2. **네트워크 구성** — Network 페이지에서 VPC/서브넷 생성
3. **인터넷 연결** — Network 페이지에서 라우팅 테이블 + 인터넷 게이트웨이 생성 및 연결
4. **인스턴스 생성** — Instance 페이지에서 이미지, 플레이버, 서브넷 등을 선택 후 생성
5. **플로팅 IP 연결** — Instance 페이지에서 인스턴스에 공인 IP 할당

## 서버 배포 (Ubuntu)

`user_data.sh`를 인스턴스 생성 시 사용자 스크립트로 사용하면 자동 배포됩니다.

```bash
# 서비스 상태 확인
systemctl status streamlit

# 실시간 로그
journalctl -u streamlit -f
```
## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | Python 3 |
| UI | Streamlit |
| HTTP | requests |
| 환경 변수 | python-dotenv |
| 대상 클라우드 | NHN Cloud (kr1 리전) |
