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
    try:    return f"${float(v):,.2f}"
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

def safe_list_of_dicts(val):
    """Return only dict items from a list, or empty list."""
    if not isinstance(val, list): return []
    return [x for x in val if isinstance(x, dict)]

def safe_str(val):
    if val is None: return "—"
    if isinstance(val, (dict, list)): return json.dumps(val)
    return str(val)

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
            Report ID:&nbsp;<code>{data.get('id','N/A')}</code>&nbsp;|&nbsp;
            Screened:&nbsp;{fmt_ts(data.get('created_at'))}&nbsp;|&nbsp;
            Wallet:&nbsp;<code>{address}</code>
        </p>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score (raw)",     f"{float(score):.2f} / 10" if score is not None else "—")
    c2.metric("Risk Score (display)", f"{float(disp):.2f} / 10"  if disp  is not None else "—")
    c3.metric("Risk Evaluation",      safe_str(data.get("risk_evaluation")))
    c4.metric("Screening Type",       safe_str(data.get("type")))
    if score is not None:
        st.progress(min(float(score) / 10.0, 1.0))

# ── Section: Compliance Flags ─────────────────────────────────────────────────
def render_compliance_flags(data):
    st.markdown("### 🏛️ Compliance & Sanctions Flags")

    flag_keys = [
        ("Sanctioned",                 "is_sanctioned"),
        ("PEP (Politically Exposed)",  "is_pep"),
        ("Adverse Media",              "has_adverse_media"),
        ("Darknet Market",             "is_darknet"),
        ("Exchange",                   "is_exchange"),
        ("Mixing / Tumbling",          "is_mixer"),
        ("High Risk Jurisdiction",     "is_high_risk_jurisdiction"),
        ("Gambling",                   "is_gambling"),
        ("Ransomware",                 "is_ransomware"),
        ("Scam",                       "is_scam"),
        ("Stolen Funds",               "is_stolen_funds"),
        ("Terrorism Financing",        "is_terrorism_financing"),
        ("Child Abuse Material",       "is_csam"),
        ("ATM",                        "is_atm"),
        ("P2P Exchange",               "is_p2p_exchange"),
    ]

    # Also check inside cluster
    cluster = data.get("cluster") or {}

    active = []
    rows   = []
    for label, key in flag_keys:
        val = data.get(key)
        if val is None:
            val = cluster.get(key)   # fallback to cluster level
        rows.append({"Flag": label, "Status": bool_icon(val), "Source": "top-level" if data.get(key) is not None else ("cluster" if cluster.get(key) is not None else "—")})
        if val is True:
            active.append(label)

    if active:
        st.error("**Flags raised:** " + "  |  ".join(f"⛔ {f}" for f in active))
    else:
        st.success("No compliance flags raised.")

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # Sanctioned lists
    lists = cluster.get("sanctioned_lists") or data.get("sanctioned_lists") or []
    if lists:
        st.error("**Sanctioned Lists:** " + ", ".join(str(x) for x in lists))

# ── Section: Triggered Rules ──────────────────────────────────────────────────
def render_triggered_rules(data):
    st.markdown("### 🚨 Triggered Rules")
    rules = safe_list_of_dicts(data.get("triggered_rules"))
    if not rules:
        st.success("No AML rules triggered.")
        return
    st.warning(f"{len(rules)} rule(s) triggered")
    for r in rules:
        title = f"⚠️ **{r.get('name','Unnamed')}**"
        score = r.get("risk_score")
        rtype = r.get("type","—")
        with st.expander(f"{title} — Score: {score} | Type: {rtype}"):
            c1, c2, c3 = st.columns(3)
            c1.metric("Rule ID",    safe_str(r.get("id")))
            c2.metric("Risk Score", safe_str(r.get("risk_score")))
            c3.metric("Rule Type",  safe_str(r.get("type")))
            if r.get("description"):
                st.info(r["description"])
            sub_exps = safe_list_of_dicts(r.get("exposures"))
            if sub_exps:
                st.write("**Contributing exposures:**")
                st.dataframe(pd.DataFrame(sub_exps), use_container_width=True, hide_index=True)
            st.json(r)

# ── Section: Exposures ────────────────────────────────────────────────────────
def render_exposures(data):
    st.markdown("### 💰 Exposure Analysis")

    # Elliptic nests exposures under behaviours[].exposures or top-level
    def extract_exposures(key):
        raw = data.get(key) or []
        # Sometimes it's a dict with sub-keys
        if isinstance(raw, dict):
            combined = []
            for v in raw.values():
                combined.extend(safe_list_of_dicts(v) if isinstance(v, list) else [])
            return combined
        return safe_list_of_dicts(raw)

    all_exp      = extract_exposures("exposures")
    direct_exp   = extract_exposures("direct_exposure")
    indirect_exp = extract_exposures("indirect_exposure")
    contrib      = extract_exposures("contributions")

    # Also look inside "behaviours" which Elliptic sometimes uses
    behaviours = safe_list_of_dicts(data.get("behaviours") or [])
    if behaviours and not all_exp:
        for b in behaviours:
            all_exp.extend(safe_list_of_dicts(b.get("exposures") or []))

    def exp_table_and_chart(exps, label):
        if not exps:
            st.info(f"No {label} data returned.")
            return
        rows = []
        for e in exps:
            rows.append({
                "Entity":       e.get("entity_name") or e.get("counterparty_name") or e.get("category") or "—",
                "Category":     safe_str(e.get("category")),
                "Sub-Category": safe_str(e.get("sub_category")),
                "Direction":    safe_str(e.get("direction")),
                "Value (USD)":  fmt_usd(e.get("value_usd") or e.get("amount_usd")),
                "% of Total":   fmt_pct(e.get("percentage")),
                "Risk Score":   safe_str(e.get("risk_score")),
                "Sanctioned":   bool_icon(e.get("is_sanctioned")),
                "Darknet":      bool_icon(e.get("is_darknet")),
                "Exchange":     bool_icon(e.get("is_exchange")),
                "Mixer":        bool_icon(e.get("is_mixer")),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # Bar chart
        chart = []
        for e in exps:
            val = e.get("value_usd") or e.get("amount_usd")
            try:
                usd = float(val)
            except (TypeError, ValueError):
                usd = 0
            if usd > 0:
                chart.append({
                    "Entity": e.get("entity_name") or e.get("counterparty_name") or e.get("category") or "Unknown",
                    "USD": usd,
                })
        if chart:
            cdf = pd.DataFrame(chart).sort_values("USD", ascending=False).head(12)
            st.markdown(f"**{label} — by Entity (USD)**")
            st.bar_chart(cdf.set_index("Entity")["USD"])

    tabs = st.tabs(["All Exposures", "Direct", "Indirect", "Contributions"])
    with tabs[0]: exp_table_and_chart(all_exp,      "All Exposure")
    with tabs[1]: exp_table_and_chart(direct_exp,   "Direct Exposure")
    with tabs[2]: exp_table_and_chart(indirect_exp, "Indirect Exposure")
    with tabs[3]:
        contrib_dicts = safe_list_of_dicts(contrib)
        if not contrib_dicts:
            st.info("No contribution data returned.")
        else:
            rows = [{"Entity": c.get("entity_name","—"), "Category": c.get("category","—"),
                     "Contribution": fmt_pct(c.get("contribution")), "Risk Score": safe_str(c.get("risk_score")),
                     "Value (USD)": fmt_usd(c.get("value_usd"))} for c in contrib_dicts]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ── Section: Cluster ──────────────────────────────────────────────────────────
def render_cluster(data):
    st.markdown("### 🔗 Cluster / Entity Information")
    cluster = data.get("cluster")
    if not isinstance(cluster, dict) or not cluster:
        st.info("No cluster data returned.")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Cluster ID",    safe_str(cluster.get("id")))
    c2.metric("Entity Name",   safe_str(cluster.get("entity_name") or cluster.get("name")))
    c3.metric("Category",      safe_str(cluster.get("category")))
    c4.metric("Addresses",     fmt_num(cluster.get("address_count")))

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Sanctioned",    bool_icon(cluster.get("is_sanctioned")))
    c6.metric("Darknet",       bool_icon(cluster.get("is_darknet")))
    c7.metric("Exchange",      bool_icon(cluster.get("is_exchange")))
    c8.metric("Mixer",         bool_icon(cluster.get("is_mixer")))

    if cluster.get("heuristics"):
        st.markdown("**Clustering heuristics:** " + ", ".join(str(h) for h in cluster["heuristics"]))

    with st.expander("Full cluster JSON"):
        st.json(cluster)

# ── Section: Blockchain Activity ──────────────────────────────────────────────
def render_blockchain_activity(data):
    st.markdown("### 📊 On-Chain Activity")

    act = None
    for key in ("blockchain_info", "activity", "address_stats", "address_info"):
        candidate = data.get(key)
        if isinstance(candidate, dict) and candidate:
            act = candidate
            break

    if not act:
        st.info("No on-chain activity data returned.")
        return

    r1c1, r1c2, r1c3, r1c4 = st.columns(4)
    r1c1.metric("Total Received", fmt_usd(act.get("total_received_usd") or act.get("received_usd")))
    r1c2.metric("Total Sent",     fmt_usd(act.get("total_sent_usd")     or act.get("sent_usd")))
    r1c3.metric("Balance",        fmt_usd(act.get("balance_usd")        or act.get("current_balance_usd")))
    r1c4.metric("Total Txns",     fmt_num(act.get("tx_count")           or act.get("transaction_count")))

    r2c1, r2c2, r2c3, r2c4 = st.columns(4)
    r2c1.metric("Sent Txns",      fmt_num(act.get("sent_tx_count")))
    r2c2.metric("Received Txns",  fmt_num(act.get("received_tx_count")))
    r2c3.metric("First Seen",     fmt_ts(act.get("first_seen") or act.get("first_transaction_time")))
    r2c4.metric("Last Seen",      fmt_ts(act.get("last_seen")  or act.get("last_transaction_time")))

    with st.expander("Full blockchain info JSON"):
        st.json(act)

# ── Section: Sanctions ────────────────────────────────────────────────────────
def render_sanctions(data):
    st.markdown("### ⚖️ Sanctions Detail")

    # Pull from multiple possible locations
    sanctions = []

    # Top-level sanctions list
    for key in ("sanctions_details", "sanctions", "sanctions_hits"):
        val = data.get(key)
        if isinstance(val, list):
            sanctions.extend(safe_list_of_dicts(val))

    # Inside cluster
    cluster = data.get("cluster") or {}
    for key in ("sanctions_details", "sanctions"):
        val = cluster.get(key)
        if isinstance(val, list):
            sanctions.extend(safe_list_of_dicts(val))

    # Inside triggered_rules looking for sanction type rules
    for rule in safe_list_of_dicts(data.get("triggered_rules")):
        if "sanction" in str(rule.get("type","")).lower() or "sanction" in str(rule.get("name","")).lower():
            sanctions.append(rule)

    if sanctions:
        rows = []
        for s in sanctions:
            rows.append({
                "Name / Programme": s.get("name") or s.get("programme") or s.get("entity_name") or "—",
                "List":             safe_str(s.get("list") or s.get("sanction_list")),
                "Programme":        safe_str(s.get("programme")),
                "Date":             safe_str(s.get("date") or s.get("listed_date")),
                "Type":             safe_str(s.get("type")),
            })
        st.error(f"⛔ {len(rows)} sanctions record(s) found")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        with st.expander("Raw sanctions JSON"):
            st.json(sanctions)
    else:
        # Show sanctioned lists from cluster even if no detail records
        lists = cluster.get("sanctioned_lists") or data.get("sanctioned_lists") or []
        if lists:
            st.error("Wallet cluster appears on: " + ", ".join(str(x) for x in lists))
        else:
            is_sanc = data.get("is_sanctioned") or cluster.get("is_sanctioned")
            if is_sanc:
                st.error("⛔ Wallet is flagged as sanctioned but no detailed records were returned by the API.")
            else:
                st.success("✅ No sanctions records found.")

# ── Section: Key Data Explorer ────────────────────────────────────────────────
def render_data_explorer(data):
    st.markdown("### 🗂️ All Returned API Fields")
    st.caption("Every key returned by the Elliptic API for this wallet — useful for discovering available data.")

    def describe(val):
        if val is None:         return ("null",   "—")
        if isinstance(val, bool):  return ("bool",   str(val))
        if isinstance(val, (int, float)): return ("number", str(val))
        if isinstance(val, str):   return ("string", val[:120])
        if isinstance(val, list):  return ("list",   f"{len(val)} items — first: {json.dumps(val[0])[:80] if val else 'empty'}")
        if isinstance(val, dict):  return ("object", f"{len(val)} keys: {', '.join(list(val.keys())[:8])}")
        return ("other", str(val)[:80])

    rows = []
    for k, v in data.items():
        dtype, preview = describe(v)
        rows.append({"Key": k, "Type": dtype, "Preview": preview})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown("#### Full Raw JSON")
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
        "⚖️ Sanctions",
        "🗂️ Data Explorer",
    ])
    with tabs[0]: render_compliance_flags(data)
    with tabs[1]: render_triggered_rules(data)
    with tabs[2]: render_exposures(data)
    with tabs[3]: render_cluster(data)
    with tabs[4]: render_blockchain_activity(data)
    with tabs[5]: render_sanctions(data)
    with tabs[6]: render_data_explorer(data)

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
