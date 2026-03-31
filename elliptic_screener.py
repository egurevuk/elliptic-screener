"""
Elliptic Wallet Screener — Streamlit App
Screens Tron USDT wallets using the Elliptic Synchronous Screening API.

Install dependencies:
    pip install streamlit requests pandas

Run:
    streamlit run elliptic_screener.py
"""

import hashlib
import hmac
import json
import time
import requests
import streamlit as st
import pandas as pd
from datetime import datetime, timezone

# ── Constants ────────────────────────────────────────────────────────────────
BASE_URL = "https://aml-api.elliptic.co"
WALLET_ENDPOINT = "/v2/wallet/synchronous"

# ── Elliptic HMAC Auth ────────────────────────────────────────────────────────
def build_headers(api_key: str, api_secret: str, method: str, path: str, body: str) -> dict:
    """Build Elliptic HMAC-SHA256 signed request headers."""
    timestamp = str(int(time.time() * 1000))
    msg = timestamp + method.upper() + path + body
    signature = hmac.new(
        bytes.fromhex(api_secret),          # secret is hex-encoded, must decode to raw bytes
        msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Content-Type": "application/json",
        "x-access-key": api_key,
        "x-access-sign": signature,
        "x-access-timestamp": timestamp,
    }

# ── API Call ──────────────────────────────────────────────────────────────────
def screen_wallet(api_key: str, api_secret: str, address: str) -> dict:
    """
    POST /v2/wallet/synchronous
    Blockchain: tron, Asset: USDT (TRC-20)
    """
    payload = {
        "subject": {
            "asset": "USDT",
            "blockchain": "tron",
            "type": "address",
            "hash": address,
        },
        "type": "wallet_exposure",
    }
    # Must use compact separators and the EXACT same string for signing and sending
    body_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    path = WALLET_ENDPOINT
    headers = build_headers(api_key, api_secret, "POST", path, body_str)

    resp = requests.post(
        BASE_URL + path,
        headers=headers,
        data=body_str.encode("utf-8"),   # send as raw bytes, not re-serialized
        timeout=60,
    )

    # Surface detailed error info for debugging
    if not resp.ok:
        st.error(f"HTTP {resp.status_code} — Raw response: `{resp.text}`")
        resp.raise_for_status()

    return resp.json()

# ── Formatting helpers ────────────────────────────────────────────────────────
def risk_color(score) -> str:
    if score is None:
        return "gray"
    if score >= 7:
        return "red"
    if score >= 4:
        return "orange"
    return "green"

def risk_label(score) -> str:
    if score is None:
        return "Unknown"
    if score >= 7:
        return "🔴 HIGH RISK"
    if score >= 4:
        return "🟠 MEDIUM RISK"
    return "🟢 LOW RISK"

def fmt_pct(val) -> str:
    try:
        return f"{float(val) * 100:.2f}%"
    except Exception:
        return str(val)

def fmt_usd(val) -> str:
    try:
        return f"${float(val):,.2f}"
    except Exception:
        return str(val)

# ── Render report ─────────────────────────────────────────────────────────────
def render_report(data: dict, address: str):
    st.divider()
    st.subheader("📋 Screening Report")

    # ── Top-level identifiers
    report_id = data.get("id", "N/A")
    created_at = data.get("created_at", "")
    try:
        ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        created_fmt = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        created_fmt = created_at

    col1, col2 = st.columns(2)
    col1.metric("Report ID", report_id)
    col2.metric("Screened At", created_fmt)
    st.code(f"Wallet: {address}", language="")

    # ── Risk score banner
    risk_score = data.get("risk_score")
    risk_score_display = data.get("risk_score_display") or risk_score

    st.markdown("---")
    st.markdown(f"### Overall Risk Score: {risk_label(risk_score)}")
    if risk_score is not None:
        st.progress(min(float(risk_score) / 10.0, 1.0))
        colA, colB = st.columns(2)
        colA.metric("Risk Score (raw)", f"{risk_score:.2f} / 10")
        if risk_score_display is not None:
            colB.metric("Risk Score (display)", f"{risk_score_display:.2f} / 10")

    # ── Triggered rules / alerts
    st.markdown("---")
    st.markdown("### 🚨 Triggered Rules")
    rules = data.get("triggered_rules", []) or []
    if rules:
        for rule in rules:
            with st.expander(f"⚠️ {rule.get('name', 'Unnamed Rule')} — Score: {rule.get('risk_score', 'N/A')}"):
                st.json(rule)
    else:
        st.success("No rules triggered.")

    # ── Exposure breakdown
    st.markdown("---")
    st.markdown("### 💰 Exposure Breakdown")

    exposures = data.get("exposures", []) or []
    if exposures:
        rows = []
        for exp in exposures:
            rows.append({
                "Entity / Category": exp.get("entity_name") or exp.get("category", "Unknown"),
                "Category": exp.get("category", ""),
                "Direction": exp.get("direction", ""),
                "Value (USD)": fmt_usd(exp.get("value_usd")),
                "% of Total": fmt_pct(exp.get("percentage")),
                "Risk Score": exp.get("risk_score", ""),
                "Is Sanctioned": "⛔ Yes" if exp.get("is_sanctioned") else "✅ No",
                "Is Darknet": "⛔ Yes" if exp.get("is_darknet") else "✅ No",
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # Charts
        chart_data = [
            {"Entity": r["Entity / Category"], "USD": float(e.get("value_usd", 0) or 0)}
            for r, e in zip(rows, exposures)
            if e.get("value_usd")
        ]
        if chart_data:
            chart_df = pd.DataFrame(chart_data).sort_values("USD", ascending=False).head(15)
            st.bar_chart(chart_df.set_index("Entity"))
    else:
        st.info("No exposure data returned.")

    # ── Counterparty cluster info
    st.markdown("---")
    st.markdown("### 🔗 Cluster / Counterparty Info")
    cluster = data.get("cluster") or {}
    if cluster:
        c1, c2, c3 = st.columns(3)
        c1.metric("Cluster ID", cluster.get("id", "N/A"))
        c2.metric("Entity Name", cluster.get("entity_name") or "Unknown")
        c3.metric("Entity Category", cluster.get("category") or "N/A")
        sub1, sub2 = st.columns(2)
        sub1.metric("Addresses in Cluster", cluster.get("address_count", "N/A"))
        sub2.metric("Is Sanctioned", "⛔ Yes" if cluster.get("is_sanctioned") else "✅ No")
        with st.expander("Full cluster data"):
            st.json(cluster)
    else:
        st.info("No cluster data returned.")

    # ── Blockchain activity summary
    st.markdown("---")
    st.markdown("### 📊 Blockchain Activity")
    activity = data.get("blockchain_info") or data.get("activity") or {}
    if activity:
        cols = st.columns(3)
        fields = [
            ("Total Received (USD)", fmt_usd(activity.get("total_received_usd"))),
            ("Total Sent (USD)", fmt_usd(activity.get("total_sent_usd"))),
            ("Tx Count", activity.get("tx_count", "N/A")),
            ("First Seen", activity.get("first_seen", "N/A")),
            ("Last Seen", activity.get("last_seen", "N/A")),
            ("Balance (USD)", fmt_usd(activity.get("balance_usd"))),
        ]
        for i, (label, val) in enumerate(fields):
            cols[i % 3].metric(label, val)
        with st.expander("Full blockchain info"):
            st.json(activity)
    else:
        st.info("No blockchain activity data returned.")

    # ── Sanctions / PEP flags
    st.markdown("---")
    st.markdown("### 🏛️ Sanctions & Compliance Flags")
    flags = {
        "Sanctioned": data.get("is_sanctioned"),
        "PEP (Politically Exposed Person)": data.get("is_pep"),
        "Adverse Media": data.get("has_adverse_media"),
        "Darknet Market": data.get("is_darknet"),
        "Exchange": data.get("is_exchange"),
        "Mixing / Tumbling": data.get("is_mixer"),
    }
    flag_rows = [
        {"Flag": k, "Status": ("⛔ Yes" if v else ("✅ No" if v is False else "❓ Unknown"))}
        for k, v in flags.items()
    ]
    st.table(pd.DataFrame(flag_rows))

    # ── Raw JSON (collapsible)
    st.markdown("---")
    with st.expander("🔍 Full Raw API Response (JSON)"):
        st.json(data)

# ── Streamlit UI ──────────────────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="Elliptic Wallet Screener",
        page_icon="🔍",
        layout="wide",
    )
    st.title("🔍 Elliptic Wallet Screener")
    st.caption("Screen Tron (TRC-20 / USDT) wallets for AML exposure using the Elliptic API.")

    # ── Sidebar: credentials
    with st.sidebar:
        st.header("🔑 API Credentials")
        st.warning("Never share your API credentials. Enter them here — they are NOT stored.")
        api_key = st.text_input("API Key", type="password", placeholder="your-api-key")
        api_secret = st.text_input("API Secret", type="password", placeholder="your-api-secret")
        st.divider()
        st.markdown("**Blockchain:** Tron")
        st.markdown("**Asset:** USDT (TRC-20)")
        st.markdown("**Endpoint:** `POST /v2/wallet/synchronous`")
        st.markdown("[📖 Elliptic API Docs](https://developers.elliptic.co/docs/quick-start-sdks)")

    # ── Main: wallet input
    address = st.text_input(
        "Tron Wallet Address",
        placeholder="e.g. TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs",
        help="Enter a valid Tron (TRC-20) wallet address starting with T",
    )

    screen_btn = st.button("🔎 Screen Wallet", type="primary", use_container_width=True)

    if screen_btn:
        if not api_key or not api_secret:
            st.error("Please enter your Elliptic API Key and Secret in the sidebar.")
            st.stop()
        if not address or not address.strip().startswith("T"):
            st.error("Please enter a valid Tron wallet address (starts with 'T').")
            st.stop()

        with st.spinner("Contacting Elliptic API…"):
            try:
                result = screen_wallet(api_key.strip(), api_secret.strip(), address.strip())
                st.success("Screening complete!")
                render_report(result, address.strip())
            except requests.HTTPError as e:
                st.error(f"API Error {e.response.status_code}: {e.response.text}")
            except requests.ConnectionError:
                st.error("Connection error — check your network or the Elliptic API endpoint.")
            except Exception as e:
                st.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
