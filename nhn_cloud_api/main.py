import streamlit as st

st.set_page_config(page_title="NHN Cloud Provisioning", layout="wide")

st.title("NHN Cloud Infrastructure Provisioning")

st.markdown(
    """
    ### 사이드바에서 페이지를 선택하세요

    - **network** — VPC / 서브넷 생성 및 네트워크 리소스 조회
    - **instance** — 이미지·플레이버·서브넷 선택 후 인스턴스 생성
    """
)
