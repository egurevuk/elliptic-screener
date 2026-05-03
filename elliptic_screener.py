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
    timestamp    = str(int(time.time() * 1000))
    message      = timestamp + method.upper() + path + body
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
    r    = requests.post(BASE_URL + WALLET_PATH, headers=hdrs, data=body.encode(), timeout=60)
    if not r.ok:
        st.error(f"HTTP {r.status_code} — `{r.text}`")
        r.raise_for_status()
    return r.json()

# ── Helpers ───────────────────────────────────────────────────────────────────
def fmt_usd(v):
    try:    return f"${float(v):,.2f}"
    except: return "—"

def fmt_pct(v):
    try:    return f"{float(v):.4f}%"
    except: return "—"

def fmt_ts(v):
    if not v: return "—"
    try:
        ts = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return ts.strftime("%Y-%m-%d %H:%M UTC")
    except:
        return str(v)

def safe_str(v):
    if v is None:              return "—"
    if isinstance(v, bool):    return "Yes" if v else "No"
    if isinstance(v, (dict, list)): return json.dumps(v)
    return str(v)

def bool_icon(v):
    if v is True:  return "⛔ Yes"
    if v is False: return "✅ No"
    return "—"

def risk_badge(score):
    if score is None: return "❓ Unknown", "#888888"
    s = float(score)               # API returns score directly (0–10 scale)
    if s >= 7:  return f"🔴 HIGH RISK ({s:.4f}/10)",   "#ff4b4b"
    if s >= 4:  return f"🟠 MEDIUM RISK ({s:.4f}/10)", "#ffa500"
    return           f"🟢 LOW RISK ({s:.4f}/10)",      "#21c354"

# ── Section: Header ───────────────────────────────────────────────────────────
def render_header(data, address):
    score        = data.get("risk_score")           # 0–1 float
    label, color = risk_badge(score)

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

    if score is not None:
        st.progress(min(float(score) / 10.0, 1.0))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score (0–10)",  f"{float(score):.4f}" if score is not None else "—")
    c2.metric("Asset Tier",         safe_str(data.get("asset_tier")))
    c3.metric("Workflow Status",    safe_str(data.get("workflow_status")))
    c4.metric("Process Status",     safe_str(data.get("process_status")))

    # Directional risk split
    rsd = data.get("risk_score_detail") or {}
    if isinstance(rsd, dict) and rsd:
        st.markdown("#### Risk Score by Direction")
        src_score = rsd.get("source")
        dst_score = rsd.get("destination")
        d1, d2 = st.columns(2)
        d1.metric("📥 Source (Incoming) Risk",     f"{float(src_score):.4f}/10" if src_score is not None else "—")
        d2.metric("📤 Destination (Outgoing) Risk", f"{float(dst_score):.4f}/10" if dst_score is not None else "—")

# ── Section: Cluster Entities ─────────────────────────────────────────────────
def render_cluster_entities(data):
    st.markdown("### 🔗 Wallet Cluster Identity")

    # cluster_entities sits at top level (parallel to analysed_by in real response)
    entities = []
    if isinstance(data.get("cluster_entities"), list):
        entities = [e for e in data["cluster_entities"] if isinstance(e, dict)]
    elif isinstance(data.get("analysed_by"), dict):
        ab = data["analysed_by"]
        if isinstance(ab.get("cluster_entities"), list):
            entities = [e for e in ab["cluster_entities"] if isinstance(e, dict)]

    bi_cluster = (data.get("blockchain_info") or {}).get("cluster") or {}

    if not entities and not bi_cluster:
        st.info("No cluster identity data returned.")
        return

    # Blockchain cluster financials
    if bi_cluster:
        st.markdown("#### 💹 Cluster Financial Summary")
        inflow  = (bi_cluster.get("inflow_value")  or {}).get("usd")
        outflow = (bi_cluster.get("outflow_value") or {}).get("usd")
        f1, f2, f3 = st.columns(3)
        f1.metric("Total Inflow (USD)",  fmt_usd(inflow))
        f2.metric("Total Outflow (USD)", fmt_usd(outflow))
        try:
            net = float(inflow or 0) - float(outflow or 0)
            f3.metric("Net Flow (USD)", fmt_usd(net))
        except:
            f3.metric("Net Flow (USD)", "—")

    # Entity table
    if entities:
        st.markdown("#### 🏷️ Identified Entities")
        rows = []
        for e in entities:
            rows.append({
                "Name":            e.get("name", "—"),
                "Category":        e.get("category", "—"),
                "Is VASP":         bool_icon(e.get("is_vasp")),
                "Is Primary":      bool_icon(e.get("is_primary_entity")),
                "After Sanction Date": bool_icon(e.get("is_after_sanction_date")),
                "Entity ID":       e.get("entity_id", "—"),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ── Evaluation detail rules renderer ─────────────────────────────────────────
def render_eval_rules(rules, direction_label):
    """Render evaluation_detail source/destination rule list."""
    if not rules:
        st.info(f"No {direction_label} evaluation rules.")
        return

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_name  = rule.get("rule_name", "Unnamed Rule")
        risk_score = rule.get("risk_score", 0)
        risk_10    = float(risk_score) * 10 if risk_score else 0
        rule_type  = rule.get("rule_type", "—")

        color = "#ff4b4b" if risk_10 >= 7 else ("#ffa500" if risk_10 >= 4 else "#21c354")
        with st.expander(
            f"{'🔴' if risk_10>=7 else '🟠' if risk_10>=4 else '🟢'} "
            f"**{rule_name}** — Risk Score: {risk_10:.4f}/10 | Type: {rule_type}"
        ):
            matched = rule.get("matched_elements") or []
            if not matched:
                st.info("No matched elements.")
                continue

            for elem in matched:
                if not isinstance(elem, dict):
                    continue

                category = elem.get("category", "Unknown Category")
                cat_pct  = elem.get("contribution_percentage", 0)
                cat_usd  = (elem.get("contribution_value") or {}).get("usd")
                indir_pct= elem.get("indirect_percentage", 0)
                indir_usd= (elem.get("indirect_value") or {}).get("usd")

                st.markdown(f"**Category: {category}**")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Category Contribution %", fmt_pct(cat_pct))
                m2.metric("Category Value (USD)",     fmt_usd(cat_usd))
                m3.metric("Indirect %",               fmt_pct(indir_pct))
                m4.metric("Indirect Value (USD)",     fmt_usd(indir_usd))

                # Individual entity contributions
                contributions = elem.get("contributions") or []
                contrib_dicts = [c for c in contributions if isinstance(c, dict)]
                if contrib_dicts:
                    st.markdown("**Flagged Entities within this category:**")
                    rows = []
                    for c in contrib_dicts:
                        rt = c.get("risk_triggers") or {}
                        rows.append({
                            "Entity":              c.get("entity", "—"),
                            "Contribution %":      fmt_pct(c.get("contribution_percentage")),
                            "Contribution (USD)":  fmt_usd((c.get("contribution_value") or {}).get("usd")),
                            "Indirect %":          fmt_pct(c.get("indirect_percentage")),
                            "Indirect (USD)":      fmt_usd((c.get("indirect_value") or {}).get("usd")),
                            "Min Hops":            safe_str(c.get("min_number_of_hops")),
                            "Screened Addr":       bool_icon(c.get("is_screened_address")),
                            "Risk Category":       rt.get("category", "—"),
                            "Sanctioned":          bool_icon(rt.get("is_sanctioned")),
                            "Country":             ", ".join(rt.get("country", [])) if rt.get("country") else "—",
                        })
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True, hide_index=True)

                    # Highlight sanctioned entities
                    sanctioned = [r for r in rows if r["Sanctioned"] == "⛔ Yes"]
                    if sanctioned:
                        st.error(
                            "⛔ **Sanctioned entities in this category:**\n" +
                            "\n".join(f"- {r['Entity']} ({r['Contribution %']} | {r['Contribution (USD)']})"
                                      for r in sanctioned)
                        )
                st.divider()

# ── Section: Evaluation Detail ────────────────────────────────────────────────
def render_evaluation_detail(data):
    st.markdown("### 🔬 Evaluation Detail — Rule Breakdown")
    st.caption(
        "Each AML rule that matched this wallet, with the specific entities and categories "
        "that triggered it, exposure amounts, and hop distance from the screened wallet."
    )
    ev = data.get("evaluation_detail") or {}
    if not isinstance(ev, dict):
        st.info("No evaluation detail returned.")
        return

    src_rules = [r for r in (ev.get("source") or []) if isinstance(r, dict)]
    dst_rules = [r for r in (ev.get("destination") or []) if isinstance(r, dict)]

    if not src_rules and not dst_rules:
        st.success("✅ No evaluation rules matched.")
        return

    t1, t2 = st.tabs([
        f"📥 Source / Incoming ({len(src_rules)} rule{'s' if len(src_rules)!=1 else ''})",
        f"📤 Destination / Outgoing ({len(dst_rules)} rule{'s' if len(dst_rules)!=1 else ''})",
    ])
    with t1: render_eval_rules(src_rules, "source")
    with t2: render_eval_rules(dst_rules, "destination")

# ── Contributions renderer ────────────────────────────────────────────────────
def render_contribution_side(items, label):
    """Render contributions.source or contributions.destination."""
    items = [i for i in (items or []) if isinstance(i, dict)]
    if not items:
        st.info(f"No {label} contributions.")
        return

    rows = []
    for c in items:
        ents = c.get("entities") or []
        ent  = ents[0] if ents and isinstance(ents[0], dict) else {}
        rows.append({
            "Entity":              ent.get("name", "—"),
            "Category":            ent.get("category", "—"),
            "Is VASP":             bool_icon(ent.get("is_vasp")),
            "Contribution %":      fmt_pct(c.get("contribution_percentage")),
            "Contribution (USD)":  fmt_usd((c.get("contribution_value") or {}).get("usd")),
            "Counterparty %":      fmt_pct(c.get("counterparty_percentage")),
            "Counterparty (USD)":  fmt_usd((c.get("counterparty_value") or {}).get("usd")),
            "Indirect %":          fmt_pct(c.get("indirect_percentage")),
            "Indirect (USD)":      fmt_usd((c.get("indirect_value") or {}).get("usd")),
            "Min Hops":            safe_str(c.get("min_number_of_hops")),
            "Screened Addr":       bool_icon(c.get("is_screened_address")),
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Highlight sanctioned / blacklisted
    flagged = [
        r for r in rows
        if any(kw in r["Category"] for kw in ["Sanctioned", "Blacklist", "Gambling", "Darknet", "Scam", "Ransomware"])
    ]
    if flagged:
        st.warning(
            f"⚠️ **{len(flagged)} flagged counterparty(ies) in {label} flow:**\n" +
            "\n".join(
                f"- **{r['Entity']}** ({r['Category']}) — {r['Contribution %']} | {r['Contribution (USD)']}"
                for r in flagged
            )
        )

    # Bar chart — top contributors by USD
    chart_rows = []
    for c in items:
        ents = c.get("entities") or []
        ent  = ents[0] if ents and isinstance(ents[0], dict) else {}
        try:
            usd = float((c.get("contribution_value") or {}).get("usd") or 0)
        except:
            usd = 0
        if usd > 0:
            chart_rows.append({"Entity": ent.get("name", "Unknown"), "USD": usd})
    if chart_rows:
        cdf = pd.DataFrame(chart_rows).sort_values("USD", ascending=False).head(15)
        st.markdown(f"**{label} — Top Counterparties by USD Value**")
        st.bar_chart(cdf.set_index("Entity")["USD"])

# ── Section: Contributions ────────────────────────────────────────────────────
def render_contributions(data):
    st.markdown("### 💡 Counterparty Contributions")
    st.caption(
        "All counterparties whose funds have flowed through this wallet, "
        "with their percentage contribution and USD value — both direct (counterparty) "
        "and indirect (via hops)."
    )
    contrib = data.get("contributions") or {}
    if not isinstance(contrib, dict):
        st.info("No contributions data returned.")
        return

    src  = contrib.get("source") or []
    dst  = contrib.get("destination") or []

    t1, t2 = st.tabs([
        f"📥 Source / Incoming ({len(src)} entities)",
        f"📤 Destination / Outgoing ({len(dst)} entities)",
    ])
    with t1: render_contribution_side(src, "Source")
    with t2: render_contribution_side(dst, "Destination")

# ── Section: Triggered Rules ──────────────────────────────────────────────────
def render_triggered_rules(data):
    st.markdown("### 🚨 Triggered AML Rules")
    rules = [r for r in (data.get("triggered_rules") or []) if isinstance(r, dict)]
    if not rules:
        st.success("✅ No AML rules triggered for this wallet.")
        return
    st.warning(f"{len(rules)} rule(s) triggered")
    for r in rules:
        with st.expander(f"⚠️ **{r.get('name','Unnamed')}** — Score: {r.get('risk_score','N/A')}"):
            st.json(r)

# ── Section: Metadata ─────────────────────────────────────────────────────────
def render_metadata(data, address):
    st.markdown("### 📋 Screening Metadata")
    subject  = data.get("subject", {})
    customer = data.get("customer", {})

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Subject**")
        st.json(subject)
    with c2:
        st.markdown("**Customer Reference**")
        st.json(customer)

    rows = [
        ("Screening ID",      data.get("screening_id")),
        ("Report ID",         data.get("id")),
        ("Type",              data.get("type")),
        ("Asset Tier",        data.get("asset_tier")),
        ("Process Status",    data.get("process_status")),
        ("Workflow Status",   data.get("workflow_status")),
        ("Screening Source",  data.get("screening_source")),
        ("Team ID",           data.get("team_id")),
        ("Created At",        fmt_ts(data.get("created_at"))),
        ("Updated At",        fmt_ts(data.get("updated_at"))),
        ("Analysed At",       fmt_ts(data.get("analysed_at"))),
        ("Error",             safe_str(data.get("error"))),
    ]
    st.dataframe(
        pd.DataFrame([{"Field": k, "Value": safe_str(v)} for k, v in rows]),
        use_container_width=True, hide_index=True,
    )

# ── Main report ───────────────────────────────────────────────────────────────
def render_report(data, address):
    st.divider()
    render_header(data, address)

    tabs = st.tabs([
        "🔬 Evaluation Detail",
        "💡 Contributions",
        "🔗 Cluster Identity",
        "🚨 Triggered Rules",
        "📋 Metadata",
        "📄 Raw JSON",
    ])
    with tabs[0]: render_evaluation_detail(data)
    with tabs[1]: render_contributions(data)
    with tabs[2]: render_cluster_entities(data)
    with tabs[3]: render_triggered_rules(data)
    with tabs[4]: render_metadata(data, address)
    with tabs[5]:
        st.markdown("### 📄 Full Raw API Response")
        st.json(data)

# ── Streamlit UI ──────────────────────────────────────────────────────────────
def load_credentials():
    """
    Load credentials from st.secrets in multiple fallback formats:
      1. [elliptic] section:  api_key / api_secret
      2. Flat keys:           ELLIPTIC_API_KEY / ELLIPTIC_API_SECRET
    Returns (api_key, api_secret, from_secrets).
    """
    try:
        # Format 1: nested [elliptic] section
        if "elliptic" in st.secrets:
            key    = st.secrets["elliptic"].get("api_key") or st.secrets["elliptic"].get("API_KEY")
            secret = st.secrets["elliptic"].get("api_secret") or st.secrets["elliptic"].get("API_SECRET")
            if key and secret:
                return key, secret, True

        # Format 2: flat top-level keys
        key    = st.secrets.get("ELLIPTIC_API_KEY")    or st.secrets.get("elliptic_api_key")
        secret = st.secrets.get("ELLIPTIC_API_SECRET") or st.secrets.get("elliptic_api_secret")
        if key and secret:
            return key, secret, True

    except Exception:
        pass

    return None, None, False


def main():
    st.set_page_config(page_title="Elliptic Wallet Screener", page_icon="🔍", layout="wide")
    st.title("🔍 Elliptic Wallet Screener")
    st.caption("Full AML exposure report for Tron (TRC-20 / USDT) wallets via the Elliptic API.")

    api_key, api_secret, from_secrets = load_credentials()

    with st.sidebar:
        st.markdown("**Blockchain:** Tron (TRC-20)")
        st.markdown("**Asset:** USDT")
        st.markdown("[📖 Elliptic Docs](https://developers.elliptic.co/docs/quick-start-sdks)")
        st.divider()

        if from_secrets:
            st.success("🔑 API credentials loaded from `secrets.toml`")
        else:
            st.header("🔑 API Credentials")
            st.warning(
                "No `secrets.toml` found. Enter credentials manually, "
                "or create `.streamlit/secrets.toml` to avoid this step."
            )
            api_key    = st.text_input("API Key",    type="password", placeholder="your-api-key")
            api_secret = st.text_input("API Secret", type="password", placeholder="your-api-secret")

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
                result = screen_wallet(api_key.strip(), api_secret.strip(), address.strip())
                st.success("✅ Screening complete!")
                render_report(result, address.strip())
            except requests.HTTPError:
                pass
            except requests.ConnectionError:
                st.error("Connection error — check your network.")
            except Exception as e:
                st.error(f"Unexpected error: {e}")
                st.exception(e)

if __name__ == "__main__":
    main()
