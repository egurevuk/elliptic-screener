# auth.py
import streamlit as st
import extra_streamlit_components as stx
from supabase import create_client

SUPABASE_URL     = "https://wjyiwevherfllekoxufn.supabase.co"
APP_URL          = "https://elliptic-screener.streamlit.app/"
GOOGLE_LOGIN_URL = f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to={APP_URL}"
COOKIE_NAME      = "kleos_refresh_token"
COOKIE_MAX_AGE   = 60 * 24 * 60 * 60  # 60 days in seconds


@st.cache_resource
def get_supabase():
    return create_client(
        st.secrets["supabase"]["url"],
        st.secrets["supabase"]["anon_key"],
    )


def get_cookie_manager():
    # Must NOT be cached — CookieManager is a widget and must run every render
    return stx.CookieManager(key="kleos_cookie_manager")


def require_login():
    """
    Call once at the top of main(), AFTER st.set_page_config().
    Returns the authenticated user's email string.
    Persists login across page refreshes via a browser cookie (60 days).
    """
    sb = get_supabase()
    cm = get_cookie_manager()

    if "user"          not in st.session_state: st.session_state.user          = None
    if "refresh_token" not in st.session_state: st.session_state.refresh_token = None

    # ── Step 1: Handle ?code= (PKCE flow) ────────────────────────────────────
    code = st.query_params.get("code")
    if code and not st.session_state.user:
        try:
            res = sb.auth.exchange_code_for_session({"auth_code": code})
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
            cm.set(COOKIE_NAME, res.session.refresh_token, max_age=COOKIE_MAX_AGE)
        except Exception as e:
            st.error(f"Login failed: {e}")
        st.query_params.clear()
        st.rerun()
        return

    # ── Step 2: Handle ?access_token= (implicit flow) ────────────────────────
    access_token  = st.query_params.get("access_token")
    refresh_token = st.query_params.get("refresh_token")
    if access_token and not st.session_state.user:
        try:
            res = sb.auth.set_session(access_token, refresh_token or "")
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
            cm.set(COOKIE_NAME, res.session.refresh_token, max_age=COOKIE_MAX_AGE)
        except Exception as e:
            st.error(f"Login failed: {e}")
        st.query_params.clear()
        st.rerun()
        return

    # ── Step 3: Try restoring from session_state refresh token ────────────────
    if not st.session_state.user and st.session_state.refresh_token:
        try:
            res = sb.auth.refresh_session(st.session_state.refresh_token)
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
            cm.set(COOKIE_NAME, res.session.refresh_token, max_age=COOKIE_MAX_AGE)
        except Exception:
            st.session_state.user          = None
            st.session_state.refresh_token = None

    # ── Step 4: Try restoring from cookie ────────────────────────────────────
    if not st.session_state.user:
        cookie_token = cm.get(COOKIE_NAME)
        if cookie_token:
            try:
                res = sb.auth.refresh_session(cookie_token)
                st.session_state.user          = res.user
                st.session_state.refresh_token = res.session.refresh_token
                cm.set(COOKIE_NAME, res.session.refresh_token, max_age=COOKIE_MAX_AGE)
            except Exception:
                cm.delete(COOKIE_NAME)

    # ── Step 5: Show login page if still not authenticated ────────────────────
    if not st.session_state.user:
        _show_login_page(cm)
        st.stop()
        return

    return st.session_state.user.email


def show_signout_button():
    cm = get_cookie_manager()
    if st.button("Sign out", use_container_width=True):
        try:
            get_supabase().auth.sign_out()
        except Exception:
            pass
        cm.delete(COOKIE_NAME)
        st.session_state.user          = None
        st.session_state.refresh_token = None
        st.rerun()


def _show_login_page(cm):
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
