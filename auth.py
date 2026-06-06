# auth.py
import streamlit as st
from supabase import create_client


@st.cache_resource
def get_supabase():
    return create_client(
        st.secrets["supabase"]["url"],
        st.secrets["supabase"]["anon_key"],
    )


def require_login():
    """
    Call once at the top of main(), AFTER st.set_page_config().
    Returns the authenticated user's email string.
    """
    sb = get_supabase()

    if "user" not in st.session_state:
        st.session_state.user = None
    if "refresh_token" not in st.session_state:
        st.session_state.refresh_token = None

    # ── Step 1: Handle ?code= callback ───────────────────────────────────────
    code = st.query_params.get("code")
    if code and not st.session_state.user:
        with st.spinner("Signing you in…"):
            try:
                res = sb.auth.exchange_code_for_session({"auth_code": code})
                st.session_state.user          = res.user
                st.session_state.refresh_token = res.session.refresh_token
            except Exception as e:
                st.error(f"Login failed: {e}")
        st.query_params.clear()
        st.rerun()

    # ── Step 2: Restore session from refresh token ────────────────────────────
    if not st.session_state.user and st.session_state.refresh_token:
        try:
            res = sb.auth.refresh_session(st.session_state.refresh_token)
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
        except Exception:
            st.session_state.user          = None
            st.session_state.refresh_token = None

    # ── Step 3: Show login page if still not authenticated ────────────────────
    if not st.session_state.user:
        _show_login_page()
        st.stop()

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
    """Render the login page. OAuth URL is only fetched when button is clicked."""
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

        if "oauth_url" not in st.session_state:
            # Pre-generate the URL once and cache it in session state
            # so subsequent renders don't make a network call
            try:
                sb = get_supabase()
                res = sb.auth.sign_in_with_oauth({"provider": "google"})
                st.session_state.oauth_url = res.url
            except Exception as e:
                st.error(f"Could not generate login URL: {e}")
                return

        st.link_button(
            "🔵  Continue with Google",
            url=st.session_state.oauth_url,
            use_container_width=True,
            type="primary",
        )

        st.markdown(" ")
        st.caption("Contact your administrator to request access.")
