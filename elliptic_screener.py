# auth.py
import streamlit as st
import streamlit.components.v1 as components
from supabase import create_client


@st.cache_resource
def get_supabase():
    return create_client(
        st.secrets["supabase"]["url"],
        st.secrets["supabase"]["anon_key"],
    )


def require_login():
    """
    Call once at the top of main().
    Returns the authenticated user's email string.
    - Persists session across page refreshes using st.session_state
    - Silently refreshes expired tokens using the refresh_token
    - Only forces re-login if the refresh token itself is expired (default: 60 days)
    """
    sb = get_supabase()

    if "user" not in st.session_state:
        st.session_state.user = None
    if "refresh_token" not in st.session_state:
        st.session_state.refresh_token = None
    if "access_token" not in st.session_state:
        st.session_state.access_token = None

    # ── Step 1: Handle ?code= callback from Google via Supabase ───────────────
    code = st.query_params.get("code")
    if code and not st.session_state.user:
        try:
            res = sb.auth.exchange_code_for_session({"auth_code": code})
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
            st.session_state.access_token  = res.session.access_token
            st.query_params.clear()
            st.rerun()
        except Exception as e:
            st.error(f"Login failed: {e}")
            st.session_state.user = None

    # ── Step 2: If we have a refresh token but no user, try to restore session ─
    if not st.session_state.user and st.session_state.refresh_token:
        try:
            res = sb.auth.refresh_session(st.session_state.refresh_token)
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
            st.session_state.access_token  = res.session.access_token
        except Exception:
            # Refresh token expired — clear everything and force re-login
            st.session_state.user          = None
            st.session_state.refresh_token = None
            st.session_state.access_token  = None

    # ── Step 3: If still no user, show login page ─────────────────────────────
    if not st.session_state.user:
        _show_login_page(sb)
        st.stop()

    return st.session_state.user.email


def show_signout_button():
    """Call inside the sidebar after require_login()."""
    if st.button("Sign out", use_container_width=True):
        try:
            get_supabase().auth.sign_out()
        except Exception:
            pass
        st.session_state.user          = None
        st.session_state.refresh_token = None
        st.session_state.access_token  = None
        st.rerun()


def _show_login_page(sb):
    logo = st.secrets["app"].get("logo_url", "")

    try:
        res = sb.auth.sign_in_with_oauth({"provider": "google"})
        oauth_url = res.url
    except Exception as e:
        st.error(f"Could not generate login URL: {e}")
        return

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
            url=oauth_url,
            use_container_width=True,
            type="primary",
        )
        st.markdown(" ")
        st.caption("Contact your administrator to request access.")
