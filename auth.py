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
    - Handles ?code= OAuth callback
    - Persists session via refresh_token (survives page reloads)
    - Only forces re-login if refresh token expires (60 days on free plan)
    """
    sb = get_supabase()

    if "user" not in st.session_state:
        st.session_state.user = None
    if "refresh_token" not in st.session_state:
        st.session_state.refresh_token = None

    # ── Step 1: Handle ?code= callback from Google via Supabase ──────────────
    code = st.query_params.get("code")
    if code:
        # Clear the code from URL immediately to prevent reuse on refresh
        st.query_params.clear()
        if not st.session_state.user:
            with st.spinner("Signing you in…"):
                try:
                    res = sb.auth.exchange_code_for_session({"auth_code": code})
                    st.session_state.user          = res.user
                    st.session_state.refresh_token = res.session.refresh_token
                    st.rerun()
                except Exception as e:
                    st.error(f"Login failed: {e}")
                    st.session_state.user = None

    # ── Step 2: No user but we have a refresh token — restore session silently ─
    if not st.session_state.user and st.session_state.refresh_token:
        try:
            res = sb.auth.refresh_session(st.session_state.refresh_token)
            st.session_state.user          = res.user
            st.session_state.refresh_token = res.session.refresh_token
        except Exception:
            # Refresh token expired — clear and force re-login
            st.session_state.user          = None
            st.session_state.refresh_token = None

    # ── Step 3: Still no user — show login page ───────────────────────────────
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
        st.rerun()


def _show_login_page(sb):
    logo = st.secrets["app"].get("logo_url", "")

    try:
        res       = sb.auth.sign_in_with_oauth({"provider": "google"})
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
