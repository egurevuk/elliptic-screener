"""
Elliptic Wallet Screener — Full Detail Report
Screens Tron USDT wallets using the Elliptic Synchronous Screening API.

Install:
    pip install streamlit requests pandas plotly

Run:
    streamlit run elliptic_screener.py
"""

import hashlib, hmac, json, time, base64, uuid
import requests
import streamlit as st
import pandas as pd

from datetime import datetime, timezone

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_URL      = "https://aml-api.elliptic.co"
WALLET_PATH   = "/v2/wallet/synchronous"
ANALYSIS_PATH = "/v2/analyses"          # async full analysis (optional enrichment)

# ── Auth ──────────────────────────────────────────────────────────────────────
def build_headers(api_key, api_secret, method, path, body, debug=False):
    timestamp = str(int(time.time() * 1000))
    message   = timestamp + method.upper() + path + body
    try:
        secret_bytes = base64.b64decode(api_secret)
    except Exception:
        secret_bytes = api_secret.encode("utf-8")
    raw_sig   = hmac.new(secret_bytes, message.encode("utf-8"), hashlib.sha256).digest()
    signature = base64.b64encode(raw_sig).decode("utf-8")
    if debug:
        st.code(f"ts={timestamp}\nmsg={message}\nsig={signature}", language="text")
    return {
        "Content-Type":       "application/json",
        "x-access-key":       api_key,
        "x-access-sign":      signature,
        "x-access-timestamp": timestamp,
    }

def api_post(api_key, api_secret, path, payload, debug=False):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    hdrs = build_headers(api_key, api_secret, "POST", path, body, debug)
    r = requests.post(BASE_URL + path, headers=hdrs, data=body.encode(), timeout=60)
    if not r.ok:
        st.error(f"HTTP {r.status_code} — `{r.text}`")
        r.raise_for_status()
    return r.json()

def api_get(api_key, api_secret, path, debug=False):
    hdrs = build_headers(api_key, api_secret, "GET", path, "", debug)
    r = requests.get(BASE_URL + path, headers=hdrs, timeout=60)
    if not r.ok:
        st.error(f"HTTP {r.status_code} — `{r.text}`")
        r.raise_for_status()
    return r.json()

# ── Screen wallet ─────────────────────────────────────────────────────────────
def screen_wallet(api_key, api_secret, address, debug=False):
    payload = {
        "subject": {
            "asset":      "USDT",
            "blockchain": "tron",
            "type":       "address",
            "hash":       address,
        },
        "type":                "wallet_exposure",
        "customer_reference":  f"screen-{uuid.uuid4().hex[:8]}",
    }
    return api_post(api_key, api_secret, WALLET_PATH, payload, debug)

# ── Helpers ───────────────────────────────────────────────────────────────────
def fmt_usd(v):
    try:    return f"${float(v):,.2f}"
    except: return "—"

def fmt_pct(v):
    try:    return f"{float(v)*100:.2f}%"
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

def risk_badge(score):
    if score is None: return "❓ Unknown", "gray"
    s = float(score)
    if s >= 7:  return "🔴 HIGH RISK",    "#ff4b4b"
    if s >= 4:  return "🟠 MEDIUM RISK",  "#ffa500"
    return           "🟢 LOW RISK",       "#21c354"

def bool_icon(v):
    if v is True:  return "⛔ Yes"
    if v is False: return "✅ No"
    return "—"

# ── Section renderers ─────────────────────────────────────────────────────────

def render_header(data, address):
    report_id = data.get("id", "N/A")
    label, color = risk_badge(data.get("risk_score"))
    score  = data.get("risk_score")
    disp   = data.get("risk_score_display") or score

    st.markdown(f"""
    <div style="background:{color}22;border-left:6px solid {color};
                padding:16px 20px;border-radius:8px;margin-bottom:1rem">
        <h2 style="margin:0;color:{color}">{label}</h2>
        <p style="margin:4px 0 0 0;font-size:0.9rem;color:#888">
            Report&nbsp;ID:&nbsp;<code>{report_id}</code> &nbsp;|&nbsp;
            Screened:&nbsp;{fmt_ts(data.get('created_at'))} &nbsp;|&nbsp;
            Wallet:&nbsp;<code>{address}</code>
        </p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score",         f"{float(score):.2f} / 10" if score is not None else "—")
    c2.metric("Risk Score Display", f"{float(disp):.2f} / 10"  if disp  is not None else "—")
    c3.metric("Risk Evaluation",    data.get("risk_evaluation", "—") or "—")
    c4.metric("Screening Type",     data.get("type", "—"))

    if score is not None:
        st.progress(min(float(score) / 10.0, 1.0))


def render_compliance_flags(data):
    st.markdown("### 🏛️ Compliance & Sanctions Flags")
    flags = [
        ("Sanctioned",                   data.get("is_sanctioned")),
        ("PEP (Politically Exposed)",    data.get("is_pep")),
        ("Adverse Media",                data.get("has_adverse_media")),
        ("Darknet Market",               data.get("is_darknet")),
        ("Exchange",                     data.get("is_exchange")),
        ("Mixing / Tumbling",            data.get("is_mixer")),
        ("High Risk Jurisdiction",       data.get("is_high_risk_jurisdiction")),
        ("Gambling",                     data.get("is_gambling")),
        ("Ransomware",                   data.get("is_ransomware")),
        ("Scam",                         data.get("is_scam")),
        ("Stolen Funds",                 data.get("is_stolen_funds")),
        ("Terrorism Financing",          data.get("is_terrorism_financing")),
        ("Child Abuse Material",         data.get("is_csam")),
        ("ATM",                          data.get("is_atm")),
        ("P2P Exchange",                 data.get("is_p2p_exchange")),
    ]
    active   = [(k, v) for k, v in flags if v is True]
    inactive = [(k, v) for k, v in flags if v is not True]

    if active:
        st.error(f"**{len(active)} flag(s) raised:**  " + "  |  ".join(f"⛔ {k}" for k, _ in active))

    rows = [{"Flag": k, "Status": bool_icon(v)} for k, v in flags]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=200)


def render_triggered_rules(data):
    st.markdown("### 🚨 Triggered Rules")
    rules = data.get("triggered_rules") or []
    if not rules:
        st.success("No AML rules triggered.")
        return
    st.warning(f"{len(rules)} rule(s) triggered")
    for r in rules:
        with st.expander(f"⚠️ **{r.get('name','Unnamed')}** — Score: {r.get('risk_score','N/A')} | Type: {r.get('type','—')}"):
            col1, col2, col3 = st.columns(3)
            col1.metric("Rule ID",     r.get("id","—"))
            col2.metric("Risk Score",  r.get("risk_score","—"))
            col3.metric("Rule Type",   r.get("type","—"))
            if r.get("description"):
                st.info(r["description"])
            # Show any contributing exposures linked to this rule
            if r.get("exposures"):
                st.write("**Contributing exposures:**")
                st.dataframe(pd.DataFrame(r["exposures"]), use_container_width=True, hide_index=True)
            with st.expander("Raw rule JSON"):
                st.json(r)


def render_exposures(data):
    st.markdown("### 💰 Exposure Analysis")

    # Elliptic returns exposures at top level AND inside direct/indirect
    all_exp      = data.get("exposures")              or []
    direct_exp   = data.get("direct_exposure")        or []
    indirect_exp = data.get("indirect_exposure")      or []
    contrib      = data.get("contributions")          or []

    tabs = st.tabs(["All Exposures", "Direct", "Indirect", "Contributions"])

    def exp_table(exps, label):
        if not exps:
            st.info(f"No {label} data.")
            return
        rows = []
        for e in exps:
            rows.append({
                "Entity":        e.get("entity_name") or e.get("counterparty_name") or "—",
                "Category":      e.get("category","—"),
                "Sub-Category":  e.get("sub_category","—"),
                "Direction":     e.get("direction","—"),
                "Value (USD)":   fmt_usd(e.get("value_usd") or e.get("amount_usd")),
                "% of Total":    fmt_pct(e.get("percentage")),
                "Risk Score":    e.get("risk_score","—"),
                "Sanctioned":    bool_icon(e.get("is_sanctioned")),
                "Darknet":       bool_icon(e.get("is_darknet")),
                "Exchange":      bool_icon(e.get("is_exchange")),
                "Mixer":         bool_icon(e.get("is_mixer")),
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # Bar chart of USD exposure
        chart_rows = [
            {"Entity": e.get("entity_name") or e.get("counterparty_name") or e.get("category","?"),
             "USD":    float(e.get("value_usd") or e.get("amount_usd") or 0)}
            for e in exps if (e.get("value_usd") or e.get("amount_usd"))
        ]
        if chart_rows:
            cdf = pd.DataFrame(chart_rows)
            cdf = cdf[cdf["USD"] > 0].sort_values("USD", ascending=False).head(12)
            st.markdown(f"**{label} — Exposure by Entity (USD)**")
            st.bar_chart(cdf.set_index("Entity")["USD"])

    with tabs[0]: exp_table(all_exp,      "exposure")
    with tabs[1]: exp_table(direct_exp,   "direct exposure")
    with tabs[2]: exp_table(indirect_exp, "indirect exposure")
    with tabs[3]:
        if not contrib:
            st.info("No contribution data returned.")
        else:
            rows = []
            for c in contrib:
                rows.append({
                    "Entity":       c.get("entity_name","—"),
                    "Category":     c.get("category","—"),
                    "Contribution": fmt_pct(c.get("contribution")),
                    "Risk Score":   c.get("risk_score","—"),
                    "Value (USD)":  fmt_usd(c.get("value_usd")),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_cluster(data):
    st.markdown("### 🔗 Cluster / Entity Information")
    cluster = data.get("cluster") or {}
    if not cluster:
        st.info("No cluster data returned.")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Cluster ID",       cluster.get("id","—"))
    c2.metric("Entity Name",      cluster.get("entity_name") or "Unknown")
    c3.metric("Category",         cluster.get("category","—"))
    c4.metric("Addresses",        fmt_num(cluster.get("address_count")))

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Sanctioned",       bool_icon(cluster.get("is_sanctioned")))
    c6.metric("Darknet",          bool_icon(cluster.get("is_darknet")))
    c7.metric("Exchange",         bool_icon(cluster.get("is_exchange")))
    c8.metric("Mixer",            bool_icon(cluster.get("is_mixer")))

    if cluster.get("sanctioned_lists"):
        st.error("**Sanctioned Lists:** " + ", ".join(cluster["sanctioned_lists"]))

    if cluster.get("heuristics"):
        st.markdown("**Clustering Heuristics Used:**")
        st.write(", ".join(cluster["heuristics"]))

    with st.expander("Full cluster JSON"):
        st.json(cluster)


def render_blockchain_activity(data):
    st.markdown("### 📊 On-Chain Activity")

    # Elliptic may return this under several keys
    act = (data.get("blockchain_info")
           or data.get("activity")
           or data.get("address_stats")
           or {})

    if not act:
        st.info("No on-chain activity data returned.")
        return

    r1c1, r1c2, r1c3, r1c4 = st.columns(4)
    r1c1.metric("Total Received",  fmt_usd(act.get("total_received_usd") or act.get("received_usd")))
    r1c2.metric("Total Sent",      fmt_usd(act.get("total_sent_usd")     or act.get("sent_usd")))
    r1c3.metric("Balance",         fmt_usd(act.get("balance_usd")        or act.get("current_balance_usd")))
    r1c4.metric("Total Tx Count",  fmt_num(act.get("tx_count")           or act.get("transaction_count")))

    r2c1, r2c2, r2c3, r2c4 = st.columns(4)
    r2c1.metric("Sent Tx Count",   fmt_num(act.get("sent_tx_count")))
    r2c2.metric("Received Tx Count",fmt_num(act.get("received_tx_count")))
    r2c3.metric("First Seen",      fmt_ts(act.get("first_seen")  or act.get("first_transaction_time")))
    r2c4.metric("Last Seen",       fmt_ts(act.get("last_seen")   or act.get("last_transaction_time")))

    with st.expander("Full blockchain info JSON"):
        st.json(act)


def render_counterparties(data):
    st.markdown("### 🤝 Counterparty Details")
    cps = (data.get("counterparties")
           or data.get("counterparty_entities")
           or [])
    if not cps:
        st.info("No counterparty entity data returned.")
        return

    rows = []
    for cp in cps:
        rows.append({
            "Name":           cp.get("name","—"),
            "Category":       cp.get("category","—"),
            "Direction":      cp.get("direction","—"),
            "Volume (USD)":   fmt_usd(cp.get("volume_usd") or cp.get("value_usd")),
            "Tx Count":       fmt_num(cp.get("tx_count")),
            "Sanctioned":     bool_icon(cp.get("is_sanctioned")),
            "Risk Score":     cp.get("risk_score","—"),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_risk_factors(data):
    st.markdown("### 🔬 Risk Factors & Score Drivers")
    factors = (data.get("risk_factors")
               or data.get("risk_indicators")
               or data.get("score_factors")
               or [])
    if not factors:
        st.info("No explicit risk factor breakdown returned by the API for this wallet.")
        return

    rows = []
    for f in factors:
        rows.append({
            "Factor":      f.get("name") or f.get("factor","—"),
            "Weight":      fmt_pct(f.get("weight")),
            "Score":       f.get("score","—"),
            "Description": f.get("description","—"),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_sanctions_detail(data):
    st.markdown("### ⚖️ Sanctions Detail")
    sanctions = data.get("sanctions_details") or data.get("sanctions") or []
    if not sanctions:
        # Check if the cluster itself has sanctions info
        cluster = data.get("cluster") or {}
        lists   = cluster.get("sanctioned_lists") or []
        if lists:
            st.error("Wallet cluster appears on sanctioned list(s): " + ", ".join(lists))
        else:
            st.success("No sanctions records found.")
        return

    rows = [{"List": s.get("list","—"), "Entry": s.get("name","—"),
             "Programme": s.get("programme","—"), "Date": s.get("date","—")}
            for s in sanctions]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_full_json(data):
    with st.expander("🔍 Full Raw API Response (JSON)"):
        st.json(data)


# ── Main report ───────────────────────────────────────────────────────────────
def render_report(data, address):
    st.divider()
    render_header(data, address)

    tabs = st.tabs([
        "🏛️ Compliance",
        "🚨 Rules",
        "💰 Exposures",
        "🔗 Cluster",
        "📊 On-Chain",
        "🤝 Counterparties",
        "🔬 Risk Factors",
        "⚖️ Sanctions",
        "📄 Raw JSON",
    ])
    with tabs[0]: render_compliance_flags(data)
    with tabs[1]: render_triggered_rules(data)
    with tabs[2]: render_exposures(data)
    with tabs[3]: render_cluster(data)
    with tabs[4]: render_blockchain_activity(data)
    with tabs[5]: render_counterparties(data)
    with tabs[6]: render_risk_factors(data)
    with tabs[7]: render_sanctions_detail(data)
    with tabs[8]: render_full_json(data)


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
        debug_mode = st.checkbox("🐛 Debug signing", value=False)
        st.divider()
        st.markdown("**Blockchain:** Tron (TRC-20)")
        st.markdown("**Asset:** USDT")
        st.markdown("[📖 Elliptic API Docs](https://developers.elliptic.co/docs/quick-start-sdks)")

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
                data = screen_wallet(api_key.strip(), api_secret.strip(), address.strip(), debug=debug_mode)
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
