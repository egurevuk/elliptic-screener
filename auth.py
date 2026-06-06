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
    Call once at the top of main().
    Returns the authenticated user's email string.
    Blocks execution and shows login page until the user signs in.
    """
    sb = get_supabase()

    if "user" not in st.session_state:
        st.session_state.user = None

    # Supabase appends ?code= to the redirect URL after Google login
    code = st.query_params.get("code")
    if code and not st.session_state.user:
        try:
            res = sb.auth.exchange_code_for_session({"auth_code": code})
            st.session_state.user = res.user
            st.query_params.clear()
            st.rerun()
        except Exception as e:
            st.error(f"Login failed: {e}")
            st.session_state.user = None

    if not st.session_state.user:
        _show_login_page(sb)
        st.stop()

    return st.session_state.user.email


def show_signout_button():
    """Call inside the sidebar after require_login()."""
    if st.button("Sign out", use_container_width=True):
        get_supabase().auth.sign_out()
        st.session_state.user = None
        st.rerun()


def _show_login_page(sb):
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

        if st.button("🔵  Continue with Google", type="primary", use_container_width=True):
            # No redirect_to — Supabase uses the Site URL set in the dashboard
            res = sb.auth.sign_in_with_oauth({"provider": "google"})
            st.markdown(
                f'<meta http-equiv="refresh" content="0; url={res.url}">',
                unsafe_allow_html=True,
            )

        st.markdown(" ")
        st.caption("Contact your administrator to request access.")
