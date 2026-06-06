# auth.py
import streamlit as st
from supabase import create_client

SUPABASE_URL = "https://wjyiwevherfllekoxufn.supabase.co"
APP_URL      = "https://elliptic-screener.streamlit.app/"
GOOGLE_LOGIN_URL = f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to=https://egurevuk.github.io/elliptic-screener/callback.html"


@st.cache_resource
def get_supabase():
    return create_client(
        st.secrets["supabase"]["url"],
        st.secrets["supabase"]["anon_key"],
    )


def require_login():
    sb = get_supabase()

    if "user"          not in st.session_state: st.session_state.user          = None
    if "refresh_token" not in st.session_state: st.session_state.refresh_token = None

    # ── Handle ?code= (PKCE flow) ─────────────────────────────────────────────
    code = st.query_params.get("code")
    if code and not st.session_state.user:
        try:
            res = sb.auth.exchange_code_for_session({"auth_code": code})
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
        except Exception as e:
            st.error(f"Login failed (code): {e}")
        st.query_params.clear()
        st.rerun()
        return

    # ── Handle ?access_token= (implicit flow — extracted from hash by redirect page)
    access_token  = st.query_params.get("access_token")
    refresh_token = st.query_params.get("refresh_token")
    if access_token and not st.session_state.user:
        try:
            res = sb.auth.set_session(access_token, refresh_token or "")
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
        except Exception as e:
            st.error(f"Login failed (token): {e}")
        st.query_params.clear()
        st.rerun()
        return

    # ── Restore from refresh token ────────────────────────────────────────────
    if not st.session_state.user and st.session_state.refresh_token:
        try:
            res = sb.auth.refresh_session(st.session_state.refresh_token)
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
        except Exception:
            st.session_state.user          = None
            st.session_state.refresh_token = None

    # ── Show login if not authenticated ───────────────────────────────────────
    if not st.session_state.user:
        _show_login_page()
        st.stop()
        return

    return st.session_state.user.email


def show_signout_button():
    if st.button("Sign out", use_container_width=True):
        try:
            get_supabase().auth.sign_out()
        except Exception:
            pass
        st.session_state.user          = None
        st.session_state.refresh_token = None
        st.rerun()


def _show_login_page():
    logo = st.secrets["app"].get("logo_url", "")
    _, col, _ = st.columns([1, 2, 1])
    with col:
        if logo:
            st.image(logo, width=160)
        st.markdown("## AML Wallet Screener")
        st.caption("Powered by Elliptic · Tron / USDT")
        st.divider()
        st.markdown("Sign in with your Google account to continue.")
        st.markdown(" ")
        st.link_button(
            "🔵  Continue with Google",
            url=GOOGLE_LOGIN_URL,
            use_container_width=True,
            type="primary",
        )
        st.markdown(" ")
        st.caption("Contact your administrator to request access.")
