"""
Elliptic Wallet Screener — Full Detail Report
Screens Tron USDT wallets using the Elliptic Synchronous Screening API.

Install:
    pip install streamlit requests pandas

Run:
    streamlit run elliptic_screener.py
"""

import hashlib, hmac, json, time, base64, uuid
import requests
import streamlit as st
import pandas as pd
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_URL    = "https://aml-api.elliptic.co"
WALLET_PATH = "/v2/wallet/synchronous"

# ── Auth ──────────────────────────────────────────────────────────────────────
def build_headers(api_key, api_secret, method, path, body):
    timestamp = str(int(time.time() * 1000))
    message   = timestamp + method.upper() + path + body
    try:
        secret_bytes = base64.b64decode(api_secret)
    except Exception:
        secret_bytes = api_secret.encode("utf-8")
    raw_sig   = hmac.new(secret_bytes, message.encode("utf-8"), hashlib.sha256).digest()
    signature = base64.b64encode(raw_sig).decode("utf-8")
    return {
        "Content-Type":       "application/json",
        "x-access-key":       api_key,
        "x-access-sign":      signature,
        "x-access-timestamp": timestamp,
    }

def screen_wallet(api_key, api_secret, address):
    payload = {
        "subject": {
            "asset":      "USDT",
            "blockchain": "tron",
            "type":       "address",
            "hash":       address,
        },
        "type":               "wallet_exposure",
        "customer_reference": f"screen-{uuid.uuid4().hex[:8]}",
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    hdrs = build_headers(api_key, api_secret, "POST", WALLET_PATH, body)
    r = requests.post(BASE_URL + WALLET_PATH, headers=hdrs, data=body.encode(), timeout=60)
    if not r.ok:
        st.error(f"HTTP {r.status_code} — `{r.text}`")
        r.raise_for_status()
    return r.json()

# ── Helpers ───────────────────────────────────────────────────────────────────
def fmt_usd(v):
    try:    return f"${float(v):,.4f}"
    except: return "—"

def fmt_pct(v):
    try:    return f"{float(v)*100:.4f}%"
    except: return "—"

def fmt_num(v):
    try:    return f"{int(v):,}"
    except: return str(v) if v is not None else "—"

def fmt_ts(v):
    if not v: return "—"
    try:
        ts = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return ts.strftime("%Y-%m-%d %H:%M UTC")
    except:
        return str(v)

def safe_str(v):
    if v is None: return "—"
    if isinstance(v, (dict, list)): return json.dumps(v)
    return str(v)

def safe_dicts(val):
    if not isinstance(val, list): return []
    return [x for x in val if isinstance(x, dict)]

def risk_badge(score):
    if score is None: return "❓ Unknown", "#888888"
    s = float(score)
    if s >= 7:  return "🔴 HIGH RISK",   "#ff4b4b"
    if s >= 4:  return "🟠 MEDIUM RISK", "#ffa500"
    return           "🟢 LOW RISK",      "#21c354"

def bool_icon(v):
    if v is True:  return "⛔ Yes"
    if v is False: return "✅ No"
    return "—"

# ── Parse direction blocks (source / destination) ─────────────────────────────
def parse_direction_block(block):
    """
    Elliptic returns contributions / risk_score_detail / evaluation_detail as:
    { "source": [...], "destination": [...] }
    Each item in the list is a category exposure dict.
    Returns (source_rows, destination_rows) as lists of dicts ready for display.
    """
    if not isinstance(block, dict):
        return [], []

    def parse_side(side):
        rows = []
        items = block.get(side, [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    rows.append(item)
                elif isinstance(item, str):
                    rows.append({"category": item})
        elif isinstance(items, dict):
            for k, v in items.items():
                rows.append({"category": k, "value": v})
        return rows

    return parse_side("source"), parse_side("destination")

def direction_dataframe(items):
    """Turn a list of exposure dicts into a display DataFrame."""
    if not items:
        return None
    rows = []
    for e in items:
        rows.append({
            "Entity / Category": e.get("entity_name") or e.get("name") or e.get("category") or "—",
            "Category":          safe_str(e.get("category")),
            "Value (USD)":       fmt_usd(e.get("value_usd") or e.get("value") or e.get("amount_usd")),
            "% of Total":        fmt_pct(e.get("percentage") or e.get("contribution")),
            "Risk Score":        safe_str(e.get("risk_score")),
            "Tx Count":          fmt_num(e.get("tx_count")),
            "Sanctioned":        bool_icon(e.get("is_sanctioned")),
            "Darknet":           bool_icon(e.get("is_darknet")),
            "Exchange":          bool_icon(e.get("is_exchange")),
            "Mixer":             bool_icon(e.get("is_mixer")),
        })
    return pd.DataFrame(rows)

def show_direction_tabs(block, title=""):
    src, dst = parse_direction_block(block)
    if not src and not dst:
        st.info("No data returned.")
        return
    t1, t2 = st.tabs(["📥 Source (Incoming)", "📤 Destination (Outgoing)"])
    with t1:
        df = direction_dataframe(src)
        if df is not None:
            st.dataframe(df, use_container_width=True, hide_index=True)
            _bar_chart(src, f"{title} — Source")
        else:
            st.info("No source data.")
    with t2:
        df = direction_dataframe(dst)
        if df is not None:
            st.dataframe(df, use_container_width=True, hide_index=True)
            _bar_chart(dst, f"{title} — Destination")
        else:
            st.info("No destination data.")

def _bar_chart(items, label):
    chart = []
    for e in items:
        val = e.get("value_usd") or e.get("value") or e.get("amount_usd")
        try:
            usd = float(val)
        except (TypeError, ValueError):
            usd = 0
        if usd > 0:
            name = e.get("entity_name") or e.get("name") or e.get("category") or "Unknown"
            chart.append({"Entity": name, "USD": usd})
    if chart:
        cdf = pd.DataFrame(chart).sort_values("USD", ascending=False).head(12)
        st.markdown(f"**{label} (USD)**")
        st.bar_chart(cdf.set_index("Entity")["USD"])

# ── Section: Header ───────────────────────────────────────────────────────────
def render_header(data, address):
    score = data.get("risk_score")
    label, color = risk_badge(score)
    disp  = data.get("risk_score_display") or score

    st.markdown(f"""
    <div style="background:{color}22;border-left:6px solid {color};
                padding:16px 20px;border-radius:8px;margin-bottom:1rem">
        <h2 style="margin:0;color:{color}">{label}</h2>
        <p style="margin:4px 0 0;font-size:0.9rem;color:#aaa">
            Report:&nbsp;<code>{data.get('id','N/A')}</code>&nbsp;|&nbsp;
            Screened:&nbsp;{fmt_ts(data.get('created_at'))}&nbsp;|&nbsp;
            Analysed:&nbsp;{fmt_ts(data.get('analysed_at'))}&nbsp;|&nbsp;
            Status:&nbsp;<b>{data.get('process_status','—')}</b>
        </p>
        <p style="margin:4px 0 0;font-size:0.85rem;color:#aaa">
            Wallet:&nbsp;<code>{address}</code>
        </p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score",        f"{float(score):.4f}" if score is not None else "—")
    c2.metric("Asset Tier",        safe_str(data.get("asset_tier")))
    c3.metric("Workflow Status",   safe_str(data.get("workflow_status")))
    c4.metric("Screening Source",  safe_str(data.get("screening_source")))
    if score is not None:
        st.progress(min(float(score) / 10.0, 1.0))

# ── Section: Risk Score Detail ────────────────────────────────────────────────
def render_risk_score_detail(data):
    st.markdown("### 📊 Risk Score Detail")
    st.caption("Breakdown of which counterparty categories drive the risk score, split by incoming (source) and outgoing (destination) flows.")
    block = data.get("risk_score_detail")
    if not block:
        st.info("No risk score detail returned.")
        return
    show_direction_tabs(block, "Risk Score Detail")

# ── Section: Evaluation Detail ────────────────────────────────────────────────
def render_evaluation_detail(data):
    st.markdown("### 🔬 Evaluation Detail")
    st.caption("Elliptic's evaluation of each counterparty category's contribution to the overall risk evaluation.")
    block = data.get("evaluation_detail")
    if not block:
        st.info("No evaluation detail returned.")
        return
    show_direction_tabs(block, "Evaluation Detail")

# ── Section: Contributions ────────────────────────────────────────────────────
def render_contributions(data):
    st.markdown("### 💡 Risk Contributions")
    st.caption("Percentage contribution of each exposure category to the final risk score.")
    block = data.get("contributions")
    if not block:
        st.info("No contributions data returned.")
        return
    show_direction_tabs(block, "Contributions")

# ── Section: Cluster Entities ─────────────────────────────────────────────────
def render_cluster_entities(data):
    st.markdown("### 🔗 Cluster Entities (analysed_by)")
    st.caption("Known entities associated with the wallet cluster as identified by Elliptic.")

    analysed_by = data.get("analysed_by")
    entities = []
    if isinstance(analysed_by, dict):
        entities = safe_dicts(analysed_by.get("cluster_entities", []))
    elif isinstance(analysed_by, list):
        entities = safe_dicts(analysed_by)

    if not entities:
        st.info("No cluster entity data returned.")
        return

    rows = []
    for e in entities:
        rows.append({
            "Name":       e.get("name","—"),
            "Category":   e.get("category","—"),
            "Category ID":e.get("category_id","—"),
            "Sanctioned": bool_icon(e.get("is_sanctioned")),
            "Darknet":    bool_icon(e.get("is_darknet")),
            "Exchange":   bool_icon(e.get("is_exchange")),
            "Risk Score": safe_str(e.get("risk_score")),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.expander("Raw analysed_by JSON"):
        st.json(analysed_by)

# ── Section: Blockchain Info ──────────────────────────────────────────────────
def render_blockchain_info(data):
    st.markdown("### ⛓️ Blockchain Info")
    bi = data.get("blockchain_info")
    if not isinstance(bi, dict) or not bi:
        st.info("No blockchain info returned.")
        return

    # Elliptic returns blockchain_info.cluster
    cluster = bi.get("cluster")
    if isinstance(cluster, dict) and cluster:
        st.markdown("#### Wallet Cluster")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Entity Name",    cluster.get("name","—"))
        c2.metric("Category",       cluster.get("category","—"))
        c3.metric("Address Count",  fmt_num(cluster.get("address_count")))
        c4.metric("Sanctioned",     bool_icon(cluster.get("is_sanctioned")))

        c5, c6, c7, c8 = st.columns(4)
        c5.metric("Darknet",        bool_icon(cluster.get("is_darknet")))
        c6.metric("Exchange",       bool_icon(cluster.get("is_exchange")))
        c7.metric("Mixer",          bool_icon(cluster.get("is_mixer")))
        c8.metric("Has Heuristics", bool_icon(cluster.get("has_heuristics")))

        # Transaction stats from cluster
        if cluster.get("sent") or cluster.get("received"):
            st.markdown("#### Transaction Volume")
            r1, r2, r3, r4 = st.columns(4)
            sent = cluster.get("sent") or {}
            recv = cluster.get("received") or {}
            r1.metric("Sent (USD)",     fmt_usd(sent.get("usd") or sent.get("value_usd")))
            r2.metric("Received (USD)", fmt_usd(recv.get("usd") or recv.get("value_usd")))
            r3.metric("Sent Txns",      fmt_num(sent.get("tx_count")))
            r4.metric("Received Txns",  fmt_num(recv.get("tx_count")))

        with st.expander("Full cluster JSON"):
            st.json(cluster)

    # Other top-level blockchain_info keys
    other = {k: v for k, v in bi.items() if k != "cluster"}
    if other:
        with st.expander("Other blockchain_info fields"):
            st.json(other)

# ── Section: Triggered Rules ──────────────────────────────────────────────────
def render_triggered_rules(data):
    st.markdown("### 🚨 Triggered AML Rules")
    rules = safe_dicts(data.get("triggered_rules") or [])
    if not rules:
        st.success("✅ No AML rules triggered for this wallet.")
        return
    st.warning(f"{len(rules)} rule(s) triggered")
    for r in rules:
        with st.expander(f"⚠️ **{r.get('name','Unnamed')}** — Score: {r.get('risk_score','N/A')}"):
            c1, c2, c3 = st.columns(3)
            c1.metric("Rule ID",   safe_str(r.get("id")))
            c2.metric("Score",     safe_str(r.get("risk_score")))
            c3.metric("Type",      safe_str(r.get("type")))
            if r.get("description"):
                st.info(r["description"])
            st.json(r)

# ── Section: Detected Behaviors ───────────────────────────────────────────────
def render_detected_behaviors(data):
    st.markdown("### 🧠 Detected Behaviors")
    behaviors = safe_dicts(data.get("detected_behaviors") or [])
    if not behaviors:
        st.success("✅ No specific behaviors detected.")
        return
    for b in behaviors:
        with st.expander(f"🔍 {b.get('name','Behavior')}"):
            st.json(b)

# ── Section: Subject & Metadata ───────────────────────────────────────────────
def render_metadata(data, address):
    st.markdown("### 📋 Screening Metadata")
    subject  = data.get("subject", {})
    customer = data.get("customer", {})

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Subject**")
        st.json(subject)
    with col2:
        st.markdown("**Customer Reference**")
        st.json(customer)

    meta_rows = [
        ("Screening ID",       data.get("screening_id")),
        ("Report ID",          data.get("id")),
        ("Type",               data.get("type")),
        ("Asset Tier",         data.get("asset_tier")),
        ("Process Status",     data.get("process_status")),
        ("Workflow Status",    data.get("workflow_status")),
        ("Screening Source",   data.get("screening_source")),
        ("Team ID",            data.get("team_id")),
        ("Created At",         fmt_ts(data.get("created_at"))),
        ("Updated At",         fmt_ts(data.get("updated_at"))),
        ("Analysed At",        fmt_ts(data.get("analysed_at"))),
    ]
    df = pd.DataFrame([{"Field": k, "Value": safe_str(v)} for k, v in meta_rows])
    st.dataframe(df, use_container_width=True, hide_index=True)

# ── Section: Raw JSON ─────────────────────────────────────────────────────────
def render_raw(data):
    st.markdown("### 📄 Full Raw API Response")
    st.json(data)

# ── Main report ───────────────────────────────────────────────────────────────
def render_report(data, address):
    st.divider()
    render_header(data, address)

    tabs = st.tabs([
        "📊 Risk Score Detail",
        "🔬 Evaluation Detail",
        "💡 Contributions",
        "🔗 Cluster Entities",
        "⛓️ Blockchain Info",
        "🚨 Triggered Rules",
        "🧠 Behaviors",
        "📋 Metadata",
        "📄 Raw JSON",
    ])
    with tabs[0]: render_risk_score_detail(data)
    with tabs[1]: render_evaluation_detail(data)
    with tabs[2]: render_contributions(data)
    with tabs[3]: render_cluster_entities(data)
    with tabs[4]: render_blockchain_info(data)
    with tabs[5]: render_triggered_rules(data)
    with tabs[6]: render_detected_behaviors(data)
    with tabs[7]: render_metadata(data, address)
    with tabs[8]: render_raw(data)

# ── Streamlit UI ──────────────────────────────────────────────────────────────
def main():
    st.set_page_config(page_title="Elliptic Wallet Screener", page_icon="🔍", layout="wide")
    st.title("🔍 Elliptic Wallet Screener")
    st.caption("Full AML exposure report for Tron (TRC-20 / USDT) wallets via the Elliptic API.")

    with st.sidebar:
        st.header("🔑 API Credentials")
        st.warning("Credentials are used only for the current request and are never stored.")
        api_key    = st.text_input("API Key",    type="password", placeholder="your-api-key")
        api_secret = st.text_input("API Secret", type="password", placeholder="your-api-secret")
        st.divider()
        st.markdown("**Blockchain:** Tron (TRC-20)")
        st.markdown("**Asset:** USDT")
        st.markdown("[📖 Elliptic Docs](https://developers.elliptic.co/docs/quick-start-sdks)")

    address = st.text_input(
        "Tron Wallet Address",
        placeholder="e.g. TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs",
    )

    if st.button("🔎 Screen Wallet", type="primary", use_container_width=True):
        if not api_key or not api_secret:
            st.error("Enter your API Key and Secret in the sidebar.")
            st.stop()
        if not address.strip().startswith("T"):
            st.error("Enter a valid Tron address (starts with 'T').")
            st.stop()

        with st.spinner("Contacting Elliptic API…"):
            try:
                data = screen_wallet(api_key.strip(), api_secret.strip(), address.strip())
                st.success("✅ Screening complete!")
                render_report(data, address.strip())
            except requests.HTTPError:
                pass
            except requests.ConnectionError:
                st.error("Connection error — check your network.")
            except Exception as e:
                st.error(f"Unexpected error: {e}")
                st.exception(e)

if __name__ == "__main__":
    main()
