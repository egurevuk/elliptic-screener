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
import base64
import requests
import streamlit as st
import pandas as pd
from datetime import datetime, timezone

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_URL  = "https://aml-api.elliptic.co"
WALLET_PATH = "/v2/wallet/synchronous"

# ── Elliptic HMAC-SHA256 Auth ─────────────────────────────────────────────────
def build_headers(api_key: str, api_secret: str, method: str, path: str, body: str, debug: bool = False) -> dict:
    """
    Elliptic signing spec (from their Node.js SDK source):
        timestamp  = Date.now()  (ms since epoch, integer)
        message    = timestamp + METHOD + path + body
        signature  = HMAC-SHA256(key=base64_decode(api_secret), data=message)
                     encoded as BASE64 (not hex)
        headers:
            x-access-key       = api_key
            x-access-sign      = base64(signature)
            x-access-timestamp = timestamp (string)
    """
    timestamp = str(int(time.time() * 1000))
    message   = timestamp + method.upper() + path + body

    # Elliptic secrets are base64-encoded — decode to raw bytes for HMAC key
    try:
        secret_bytes = base64.b64decode(api_secret)
    except Exception:
        # Fallback: treat as plain UTF-8 if not valid base64
        secret_bytes = api_secret.encode("utf-8")

    raw_sig = hmac.new(
        secret_bytes,
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()                          # raw bytes

    signature = base64.b64encode(raw_sig).decode("utf-8")   # base64-encoded sig

    if debug:
        st.code(
            f"timestamp : {timestamp}\n"
            f"method    : {method.upper()}\n"
            f"path      : {path}\n"
            f"body      : {body}\n"
            f"message   : {message}\n"
            f"sig(b64)  : {signature}",
            language="text",
        )

    return {
        "Content-Type":       "application/json",
        "x-access-key":       api_key,
        "x-access-sign":      signature,
        "x-access-timestamp": timestamp,
    }

# ── API call ──────────────────────────────────────────────────────────────────
def screen_wallet(api_key: str, api_secret: str, address: str, debug: bool = False) -> dict:
    payload = {
        "subject": {
            "asset":      "USDT",
            "blockchain": "tron",
            "type":       "address",
            "hash":       address,
        },
        "type": "wallet_exposure",
    }

    # Compact JSON — MUST be byte-for-byte identical for signing and sending
    body_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    headers = build_headers(api_key, api_secret, "POST", WALLET_PATH, body_str, debug=debug)

    if debug:
        st.write("**Request headers:**", {k: v for k, v in headers.items() if k != "x-access-key"})

    resp = requests.post(
        BASE_URL + WALLET_PATH,
        headers=headers,
        data=body_str.encode("utf-8"),
        timeout=60,
    )

    if not resp.ok:
        st.error(f"HTTP {resp.status_code} — `{resp.text}`")
        resp.raise_for_status()

    return resp.json()

# ── Formatting helpers ────────────────────────────────────────────────────────
def risk_label(score) -> str:
    if score is None:
        return "❓ Unknown"
    s = float(score)
    if s >= 7:  return "🔴 HIGH RISK"
    if s >= 4:  return "🟠 MEDIUM RISK"
    return "🟢 LOW RISK"

def fmt_pct(val) -> str:
    try:    return f"{float(val) * 100:.2f}%"
    except: return str(val)

def fmt_usd(val) -> str:
    try:    return f"${float(val):,.2f}"
    except: return str(val)

# ── Report renderer ───────────────────────────────────────────────────────────
def render_report(data: dict, address: str):
    st.divider()
    st.subheader("📋 Screening Report")

    report_id  = data.get("id", "N/A")
    created_at = data.get("created_at", "")
    try:
        ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        created_fmt = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        created_fmt = created_at

    c1, c2 = st.columns(2)
    c1.metric("Report ID", report_id)
    c2.metric("Screened At", created_fmt)
    st.code(f"Wallet: {address}", language="")

    # ── Risk score
    risk_score = data.get("risk_score")
    risk_score_display = data.get("risk_score_display") or risk_score
    st.markdown("---")
    st.markdown(f"### Overall Risk: {risk_label(risk_score)}")
    if risk_score is not None:
        st.progress(min(float(risk_score) / 10.0, 1.0))
        ca, cb = st.columns(2)
        ca.metric("Risk Score (raw)", f"{float(risk_score):.2f} / 10")
        if risk_score_display is not None:
            cb.metric("Risk Score (display)", f"{float(risk_score_display):.2f} / 10")

    # ── Triggered rules
    st.markdown("---")
    st.markdown("### 🚨 Triggered Rules")
    rules = data.get("triggered_rules") or []
    if rules:
        for r in rules:
            with st.expander(f"⚠️ {r.get('name','Unnamed')}  —  Score: {r.get('risk_score','N/A')}"):
                st.json(r)
    else:
        st.success("No rules triggered.")

    # ── Exposure breakdown
    st.markdown("---")
    st.markdown("### 💰 Exposure Breakdown")
    exposures = data.get("exposures") or []
    if exposures:
        rows = []
        for e in exposures:
            rows.append({
                "Entity / Category":  e.get("entity_name") or e.get("category", "Unknown"),
                "Category":           e.get("category", ""),
                "Direction":          e.get("direction", ""),
                "Value (USD)":        fmt_usd(e.get("value_usd")),
                "% of Total":         fmt_pct(e.get("percentage")),
                "Risk Score":         e.get("risk_score", ""),
                "Sanctioned":         "⛔ Yes" if e.get("is_sanctioned") else "✅ No",
                "Darknet":            "⛔ Yes" if e.get("is_darknet")    else "✅ No",
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        chart_data = [
            {"Entity": e.get("entity_name") or e.get("category","?"),
             "USD":    float(e.get("value_usd") or 0)}
            for e in exposures if e.get("value_usd")
        ]
        if chart_data:
            cdf = pd.DataFrame(chart_data).sort_values("USD", ascending=False).head(15)
            st.bar_chart(cdf.set_index("Entity"))
    else:
        st.info("No exposure data returned.")

    # ── Cluster info
    st.markdown("---")
    st.markdown("### 🔗 Cluster / Entity Info")
    cluster = data.get("cluster") or {}
    if cluster:
        c1, c2, c3 = st.columns(3)
        c1.metric("Cluster ID",      cluster.get("id", "N/A"))
        c2.metric("Entity Name",     cluster.get("entity_name") or "Unknown")
        c3.metric("Category",        cluster.get("category") or "N/A")
        s1, s2 = st.columns(2)
        s1.metric("Addresses",       cluster.get("address_count", "N/A"))
        s2.metric("Sanctioned",      "⛔ Yes" if cluster.get("is_sanctioned") else "✅ No")
        with st.expander("Full cluster data"):
            st.json(cluster)
    else:
        st.info("No cluster data returned.")

    # ── Blockchain activity
    st.markdown("---")
    st.markdown("### 📊 Blockchain Activity")
    activity = data.get("blockchain_info") or data.get("activity") or {}
    if activity:
        cols = st.columns(3)
        fields = [
            ("Total Received (USD)", fmt_usd(activity.get("total_received_usd"))),
            ("Total Sent (USD)",     fmt_usd(activity.get("total_sent_usd"))),
            ("Tx Count",             activity.get("tx_count", "N/A")),
            ("First Seen",           activity.get("first_seen", "N/A")),
            ("Last Seen",            activity.get("last_seen", "N/A")),
            ("Balance (USD)",        fmt_usd(activity.get("balance_usd"))),
        ]
        for i, (label, val) in enumerate(fields):
            cols[i % 3].metric(label, val)
        with st.expander("Full blockchain info"):
            st.json(activity)
    else:
        st.info("No blockchain activity data returned.")

    # ── Compliance flags
    st.markdown("---")
    st.markdown("### 🏛️ Sanctions & Compliance Flags")
    flags = {
        "Sanctioned":                    data.get("is_sanctioned"),
        "PEP (Politically Exposed)":     data.get("is_pep"),
        "Adverse Media":                 data.get("has_adverse_media"),
        "Darknet Market":                data.get("is_darknet"),
        "Exchange":                      data.get("is_exchange"),
        "Mixing / Tumbling":             data.get("is_mixer"),
    }
    flag_rows = [
        {"Flag": k, "Status": ("⛔ Yes" if v else ("✅ No" if v is False else "❓ Unknown"))}
        for k, v in flags.items()
    ]
    st.table(pd.DataFrame(flag_rows))

    # ── Raw JSON
    st.markdown("---")
    with st.expander("🔍 Full Raw API Response"):
        st.json(data)

# ── Streamlit UI ──────────────────────────────────────────────────────────────
def main():
    st.set_page_config(page_title="Elliptic Wallet Screener", page_icon="🔍", layout="wide")
    st.title("🔍 Elliptic Wallet Screener")
    st.caption("Screen Tron (TRC-20 / USDT) wallets for AML exposure using the Elliptic API.")

    with st.sidebar:
        st.header("🔑 API Credentials")
        st.warning("Credentials are not stored and only used for the current request.")
        api_key    = st.text_input("API Key",    type="password", placeholder="your-api-key")
        api_secret = st.text_input("API Secret", type="password", placeholder="your-api-secret")
        st.divider()
        debug_mode = st.checkbox("🐛 Debug mode (show signing details)", value=False)
        st.divider()
        st.markdown("**Blockchain:** Tron  \n**Asset:** USDT (TRC-20)  \n**Endpoint:** `POST /v2/wallet/synchronous`")
        st.markdown("[📖 Elliptic Docs](https://developers.elliptic.co/docs/quick-start-sdks)")

    address = st.text_input(
        "Tron Wallet Address",
        placeholder="e.g. TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs",
        help="Valid Tron address starting with T",
    )

    if st.button("🔎 Screen Wallet", type="primary", use_container_width=True):
        if not api_key or not api_secret:
            st.error("Enter your API Key and Secret in the sidebar.")
            st.stop()
        if not address.strip().startswith("T"):
            st.error("Enter a valid Tron address (starts with 'T').")
            st.stop()

        if debug_mode:
            st.markdown("#### 🐛 Debug: Signing Details")

        with st.spinner("Contacting Elliptic API…"):
            try:
                result = screen_wallet(api_key.strip(), api_secret.strip(), address.strip(), debug=debug_mode)
                st.success("✅ Screening complete!")
                render_report(result, address.strip())
            except requests.HTTPError:
                pass   # error already shown inside screen_wallet
            except requests.ConnectionError:
                st.error("Connection error — check your network.")
            except Exception as e:
                st.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
