"""
Elliptic Wallet Screener — Full Detail Report
Screens Tron USDT wallets using the Elliptic Synchronous Screening API.

Install:
    pip install streamlit requests pandas openpyxl supabase

secrets.toml:
    [elliptic]
    api_key    = "your-elliptic-api-key"
    api_secret = "your-elliptic-api-secret"

    [supabase]
    url      = "https://wjyiwevherfllekoxufn.supabase.co"
    anon_key = "your-legacy-anon-jwt-eyJ..."

    [app]
    admin_email = "your@email.com"
    logo_url    = "https://raw.githubusercontent.com/egurevuk/elliptic-screener/main/kleos_logo.png"
"""

import hashlib, hmac, json, time, base64, uuid, io
import requests
import streamlit as st
import pandas as pd
from datetime import datetime

# ── LINE ADDED 1: import auth module ─────────────────────────────────────────
from auth import require_login, show_signout_button, get_supabase

# All other imports and code below — no Streamlit calls at module level

# ── Elliptic auth ─────────────────────────────────────────────────────────────
BASE_URL    = "https://aml-api.elliptic.co"
WALLET_PATH = "/v2/wallet/synchronous"

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

class WalletNotFoundError(Exception):
    pass

def screen_wallet(api_key, api_secret, address):
    payload = {
        "subject": {"asset": "USDT", "blockchain": "tron", "type": "address", "hash": address},
        "type":               "wallet_exposure",
        "customer_reference": f"screen-{uuid.uuid4().hex[:8]}",
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    hdrs = build_headers(api_key, api_secret, "POST", WALLET_PATH, body)
    r    = requests.post(BASE_URL + WALLET_PATH, headers=hdrs, data=body.encode(), timeout=60)
    if r.status_code == 404:
        raise WalletNotFoundError()
    if not r.ok:
        st.error(f"HTTP {r.status_code} — `{r.text}`")
        r.raise_for_status()
    return r.json()

# ── Credential loader ─────────────────────────────────────────────────────────
def load_credentials():
    try:
        if "elliptic" in st.secrets:
            key    = st.secrets["elliptic"].get("api_key") or st.secrets["elliptic"].get("API_KEY")
            secret = st.secrets["elliptic"].get("api_secret") or st.secrets["elliptic"].get("API_SECRET")
            if key and secret:
                return key, secret, True
        key    = st.secrets.get("ELLIPTIC_API_KEY")    or st.secrets.get("elliptic_api_key")
        secret = st.secrets.get("ELLIPTIC_API_SECRET") or st.secrets.get("elliptic_api_secret")
        if key and secret:
            return key, secret, True
    except Exception:
        pass
    return None, None, False

# ── Usage logging ─────────────────────────────────────────────────────────────
def log_usage(email: str, wallet: str, scan_type: str,
              wallets_count: int = 1, risk_score=None, verdict: str = None):
    try:
        get_supabase().table("usage_log").insert({
            "user_email":    email,
            "wallet":        wallet[:100] if wallet else None,
            "scan_type":     scan_type,
            "wallets_count": wallets_count,
            "risk_score":    float(risk_score) if risk_score is not None else None,
            "verdict":       verdict,
        }).execute()
    except Exception as e:
        st.warning(f"⚠️ Usage log error (non-critical): {e}")

# ── Admin stats panel ─────────────────────────────────────────────────────────
def render_admin_stats():
    try:
        rows = (
            get_supabase().table("usage_log")
            .select("user_email, scan_type, wallets_count, verdict, scanned_at")
            .order("scanned_at", desc=True)
            .limit(500)
            .execute()
        )
        if not rows.data:
            st.info("No usage data yet.")
            return
        df = pd.DataFrame(rows.data)
        df["scanned_at"] = pd.to_datetime(df["scanned_at"]).dt.strftime("%Y-%m-%d %H:%M")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Scans",     len(df))
        m2.metric("Unique Users",    df["user_email"].nunique())
        m3.metric("Wallets Scanned", int(df["wallets_count"].sum()))
        m4.metric("Flagged",         int(df["verdict"].isin(["🟠 Medium Risk","🔴 High Risk"]).sum()))
        st.dataframe(df, use_container_width=True, hide_index=True)
        out = io.BytesIO()
        with pd.ExcelWriter(out, engine="openpyxl") as w:
            df.to_excel(w, index=False, sheet_name="Usage Log")
        out.seek(0)
        st.download_button("⬇️ Export Usage Log", data=out,
            file_name=f"usage_log_{datetime.now().strftime('%Y%m%d')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    except Exception as e:
        st.error(f"Could not load stats: {e}")

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
    if v is None:                   return "—"
    if isinstance(v, bool):         return "Yes" if v else "No"
    if isinstance(v, (dict, list)): return json.dumps(v)
    return str(v)

def bool_icon(v):
    if v is True:  return "⛔ Yes"
    if v is False: return "✅ No"
    return "—"

def risk_badge(score):
    if score is None: return "❓ Unknown", "#888888"
    s = float(score)
    if s >= 5:  return f"🔴 HIGH RISK ({s:.4f}/10)",   "#ff4b4b"
    if s >= 1:  return f"🟠 MEDIUM RISK ({s:.4f}/10)", "#ffa500"
    return           f"🟢 CLEAR ({s:.4f}/10)",          "#21c354"

def render_not_found(address):
    st.warning(
        f"**Wallet not found on the Tron blockchain.**\n\n"
        f"`{address}` has no transaction history. It either doesn't exist yet or is completely empty."
    )
    st.markdown("---")
    st.markdown("#### 💡 Want to receive USDT (TRC-20) to this address?")
    exchanges = [
        {"name": "Binance",  "url": "https://www.binance.com/en/register",  "desc": "World's largest exchange. Fast TRC-20 withdrawals.",  "icon": "🟡"},
        {"name": "Bybit",    "url": "https://www.bybit.com/en/register",    "desc": "Simple onboarding, instant USDT withdrawals.",       "icon": "🟠"},
        {"name": "OKX",      "url": "https://www.okx.com/join",             "desc": "Broad USDT support across all major networks.",      "icon": "⚫"},
        {"name": "Kraken",   "url": "https://www.kraken.com/sign-up",       "desc": "US-regulated, strong security, fiat on-ramps.",      "icon": "🔵"},
        {"name": "KuCoin",   "url": "https://www.kucoin.com/register",      "desc": "Easy TRC-20 withdrawals and low minimums.",          "icon": "🟢"},
    ]
    cols = st.columns(len(exchanges))
    for col, ex in zip(cols, exchanges):
        with col:
            st.markdown(f"**{ex['icon']} {ex['name']}**\n\n<div style='font-size:0.8rem;color:gray;margin-bottom:0.5rem'>{ex['desc']}</div>", unsafe_allow_html=True)
            st.link_button("Open account →", ex["url"], use_container_width=True)

# ── Report sections ───────────────────────────────────────────────────────────
def render_header(data, address):
    score        = data.get("risk_score")
    label, color = risk_badge(score)
    rsd          = data.get("risk_score_detail") or {}

    st.markdown(f"""
    <div style="background:{color}22;border-left:6px solid {color};
                padding:16px 20px;border-radius:8px;margin-bottom:1rem">
        <h2 style="margin:0;color:{color}">{label}</h2>
        <p style="margin:4px 0 0;font-size:0.9rem;color:#888">
            Report:&nbsp;<code>{data.get('id','N/A')}</code>&nbsp;|&nbsp;
            Screened:&nbsp;{fmt_ts(data.get('created_at'))}&nbsp;|&nbsp;
            Status:&nbsp;<b>{data.get('process_status','—')}</b>
        </p>
        <p style="margin:4px 0 0;font-size:0.85rem;color:#888">
            Wallet:&nbsp;<code>{address}</code>
        </p>
    </div>
    """, unsafe_allow_html=True)

    if score is not None:
        st.progress(min(float(score) / 10.0, 1.0))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk Score (0–10)",   f"{float(score):.4f}" if score is not None else "—")
    c2.metric("Asset Tier",          safe_str(data.get("asset_tier")))
    c3.metric("📥 Source Risk",      f"{float(rsd['source']):.4f}" if rsd.get("source") is not None else "—")
    c4.metric("📤 Destination Risk", f"{float(rsd['destination']):.4f}" if rsd.get("destination") is not None else "—")

def render_cluster_entities(data):
    st.markdown("### 🔗 Wallet Cluster Identity")
    entities = []
    if isinstance(data.get("cluster_entities"), list):
        entities = [e for e in data["cluster_entities"] if isinstance(e, dict)]
    elif isinstance(data.get("analysed_by"), dict):
        entities = [e for e in data["analysed_by"].get("cluster_entities", []) if isinstance(e, dict)]

    bi_cluster = (data.get("blockchain_info") or {}).get("cluster") or {}
    if bi_cluster:
        st.markdown("#### 💹 Cluster Financial Summary")
        inflow  = (bi_cluster.get("inflow_value")  or {}).get("usd")
        outflow = (bi_cluster.get("outflow_value") or {}).get("usd")
        f1, f2, f3 = st.columns(3)
        f1.metric("Total Inflow (USD)",  fmt_usd(inflow))
        f2.metric("Total Outflow (USD)", fmt_usd(outflow))
        try:    f3.metric("Net Flow (USD)", fmt_usd(float(inflow or 0) - float(outflow or 0)))
        except: f3.metric("Net Flow (USD)", "—")

    if entities:
        st.markdown("#### 🏷️ Identified Entities")
        rows = [{"Name": e.get("name","—"), "Category": e.get("category","—"),
                 "Is VASP": bool_icon(e.get("is_vasp")), "Is Primary": bool_icon(e.get("is_primary_entity")),
                 "After Sanction Date": bool_icon(e.get("is_after_sanction_date"))} for e in entities]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

def render_eval_rules(rules, direction_label):
    if not rules:
        st.info(f"No {direction_label} evaluation rules.")
        return
    for rule in rules:
        if not isinstance(rule, dict): continue
        risk_10 = float(rule.get("risk_score", 0)) * 10
        icon    = "🔴" if risk_10 >= 5 else ("🟠" if risk_10 >= 1 else "🟢")
        with st.expander(f"{icon} **{rule.get('rule_name','Unnamed')}** — Score: {risk_10:.4f}/10"):
            for elem in (rule.get("matched_elements") or []):
                if not isinstance(elem, dict): continue
                st.markdown(f"**Category: {elem.get('category','?')}**")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Contribution %",  fmt_pct(elem.get("contribution_percentage")))
                m2.metric("Value (USD)",      fmt_usd((elem.get("contribution_value") or {}).get("usd")))
                m3.metric("Indirect %",       fmt_pct(elem.get("indirect_percentage")))
                m4.metric("Indirect USD",     fmt_usd((elem.get("indirect_value") or {}).get("usd")))
                contrib_dicts = [c for c in (elem.get("contributions") or []) if isinstance(c, dict)]
                if contrib_dicts:
                    st.markdown("**Flagged Entities:**")
                    rows = []
                    for c in contrib_dicts:
                        rt = c.get("risk_triggers") or {}
                        rows.append({
                            "Entity":             c.get("entity","—"),
                            "Contribution %":     fmt_pct(c.get("contribution_percentage")),
                            "Contribution (USD)": fmt_usd((c.get("contribution_value") or {}).get("usd")),
                            "Indirect %":         fmt_pct(c.get("indirect_percentage")),
                            "Min Hops":           safe_str(c.get("min_number_of_hops")),
                            "Risk Category":      rt.get("category","—"),
                            "Sanctioned":         bool_icon(rt.get("is_sanctioned")),
                            "Country":            ", ".join(rt.get("country",[])) if rt.get("country") else "—",
                        })
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True, hide_index=True)
                    sanctioned = [r for r in rows if r["Sanctioned"] == "⛔ Yes"]
                    if sanctioned:
                        st.error("⛔ **Sanctioned:** " + " | ".join(r["Entity"] for r in sanctioned))
                st.divider()

def render_evaluation_detail(data):
    st.markdown("### 🔬 Evaluation Detail")
    ev = data.get("evaluation_detail") or {}
    if not isinstance(ev, dict):
        st.info("No evaluation detail returned.")
        return
    src = [r for r in (ev.get("source") or []) if isinstance(r, dict)]
    dst = [r for r in (ev.get("destination") or []) if isinstance(r, dict)]
    if not src and not dst:
        st.success("✅ No evaluation rules matched.")
        return
    t1, t2 = st.tabs([f"📥 Source ({len(src)} rules)", f"📤 Destination ({len(dst)} rules)"])
    with t1: render_eval_rules(src, "source")
    with t2: render_eval_rules(dst, "destination")

def render_contribution_side(items, label):
    items = [i for i in (items or []) if isinstance(i, dict)]
    if not items:
        st.info(f"No {label} contributions.")
        return
    rows = []
    for c in items:
        ent  = ((c.get("entities") or [{}])[0]) if isinstance((c.get("entities") or [{}])[0], dict) else {}
        rows.append({
            "Entity":             ent.get("name","—"),
            "Category":           ent.get("category","—"),
            "Is VASP":            bool_icon(ent.get("is_vasp")),
            "Contribution %":     fmt_pct(c.get("contribution_percentage")),
            "Contribution (USD)": fmt_usd((c.get("contribution_value") or {}).get("usd")),
            "Counterparty %":     fmt_pct(c.get("counterparty_percentage")),
            "Counterparty (USD)": fmt_usd((c.get("counterparty_value") or {}).get("usd")),
            "Indirect %":         fmt_pct(c.get("indirect_percentage")),
            "Indirect (USD)":     fmt_usd((c.get("indirect_value") or {}).get("usd")),
            "Min Hops":           safe_str(c.get("min_number_of_hops")),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    flagged = [r for r in rows if any(kw in r["Category"] for kw in ["Sanctioned","Blacklist","Gambling","Darknet","Scam","Ransomware"])]
    if flagged:
        st.warning("⚠️ **Flagged:** " + " | ".join(f"{r['Entity']} ({r['Category']})" for r in flagged))
    chart = []
    for c in items:
        ent = ((c.get("entities") or [{}])[0])
        name = ent.get("name","?") if isinstance(ent, dict) else "?"
        try:    usd = float((c.get("contribution_value") or {}).get("usd") or 0)
        except: usd = 0
        if usd > 0:
            chart.append({"Entity": name, "USD": usd})
    if chart:
        cdf = pd.DataFrame(chart).sort_values("USD", ascending=False).head(15)
        st.markdown(f"**{label} — Top Counterparties (USD)**")
        # Use table instead of bar_chart to avoid altair/Python 3.14 incompatibility
        cdf["Value (USD)"] = cdf["USD"].apply(lambda x: f"${x:,.2f}")
        st.dataframe(cdf[["Entity","Value (USD)"]].reset_index(drop=True),
                     use_container_width=True, hide_index=True)

def render_contributions(data):
    st.markdown("### 💡 Counterparty Contributions")
    contrib = data.get("contributions") or {}
    if not isinstance(contrib, dict):
        st.info("No contributions data returned.")
        return
    t1, t2 = st.tabs([f"📥 Source ({len(contrib.get('source') or [])} entities)",
                      f"📤 Destination ({len(contrib.get('destination') or [])} entities)"])
    with t1: render_contribution_side(contrib.get("source"), "Source")
    with t2: render_contribution_side(contrib.get("destination"), "Destination")

def render_triggered_rules(data):
    st.markdown("### 🚨 Triggered AML Rules")
    rules = [r for r in (data.get("triggered_rules") or []) if isinstance(r, dict)]
    if not rules:
        st.success("✅ No AML rules triggered.")
        return
    for r in rules:
        with st.expander(f"⚠️ **{r.get('name','Unnamed')}** — Score: {r.get('risk_score','N/A')}"):
            st.json(r)

def render_metadata(data, address):
    st.markdown("### 📋 Screening Metadata")
    rows = [
        ("Screening ID",    data.get("screening_id")),
        ("Report ID",       data.get("id")),
        ("Type",            data.get("type")),
        ("Asset Tier",      data.get("asset_tier")),
        ("Process Status",  data.get("process_status")),
        ("Workflow Status", data.get("workflow_status")),
        ("Screening Source",data.get("screening_source")),
        ("Team ID",         data.get("team_id")),
        ("Created At",      fmt_ts(data.get("created_at"))),
        ("Analysed At",     fmt_ts(data.get("analysed_at"))),
    ]
    st.dataframe(pd.DataFrame([{"Field": k, "Value": safe_str(v)} for k, v in rows]),
                 use_container_width=True, hide_index=True)

def render_report(data, address):
    st.divider()
    render_header(data, address)
    tabs = st.tabs(["🔬 Evaluation","💡 Contributions","🔗 Cluster","🚨 Rules","📋 Metadata","📄 Raw JSON"])
    with tabs[0]: render_evaluation_detail(data)
    with tabs[1]: render_contributions(data)
    with tabs[2]: render_cluster_entities(data)
    with tabs[3]: render_triggered_rules(data)
    with tabs[4]: render_metadata(data, address)
    with tabs[5]:
        st.markdown("### 📄 Full Raw API Response")
        st.json(data)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    # set_page_config MUST be the absolute first Streamlit call
    st.set_page_config(page_title="Kleos AML Screener", page_icon="🔍", layout="wide")

    # Auth gate — runs immediately after page config
    user_email = require_login()

    admin_email = st.secrets["app"].get("admin_email", "")
    logo        = st.secrets["app"].get("logo_url", "")
    api_key, api_secret, from_secrets = load_credentials()

    # ── Sidebar
    with st.sidebar:
        if logo:
            st.image(logo, width=120)
        st.divider()
        st.caption(f"👤 {user_email}")
        # ── LINE ADDED 3: sign out button ─────────────────────────────────────
        show_signout_button()
        st.divider()
        if from_secrets:
            st.success("🔑 API credentials loaded")
        else:
            st.subheader("🔑 API Credentials")
            st.warning("Add credentials to `secrets.toml`.")
            api_key    = st.text_input("API Key",    type="password")
            api_secret = st.text_input("API Secret", type="password")
        st.divider()
        st.caption("Blockchain: Tron (TRC-20)")
        st.caption("Asset: USDT")
        st.markdown("[📖 Elliptic Docs](https://developers.elliptic.co/docs/quick-start-sdks)")
        if user_email == admin_email:
            with st.expander("📊 Admin: Usage Stats"):
                render_admin_stats()

    # ── Header
    st.markdown(f"""
        <div style="display:flex;align-items:center;gap:14px;margin-bottom:0.5rem">
            {"<img src='" + logo + "' style='height:36px;width:auto'/>" if logo else ""}
            <div>
                <div style="font-size:1.5rem;font-weight:700;line-height:1.1">AML Wallet Screener</div>
                <div style="font-size:0.8rem;color:gray">Powered by Elliptic · Tron / USDT · Real-time exposure analysis</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # ── Mode toggle
    mode = st.radio("Mode", ["🔍 Single Wallet", "📂 Bulk Scan (Excel / CSV)"],
                    horizontal=True, label_visibility="collapsed")
    st.divider()

    # ══════════════════════════════════════════════════════════════════════════
    # SINGLE WALLET
    # ══════════════════════════════════════════════════════════════════════════
    if mode == "🔍 Single Wallet":
        address = st.text_input("Tron Wallet Address",
                                placeholder="e.g. TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs")
        run = st.button("🔎 Screen Wallet", type="primary")

        if run:
            if not api_key or not api_secret:
                st.error("Enter your API credentials in the sidebar.")
                st.stop()
            if not address.strip().startswith("T"):
                st.error("Enter a valid Tron address (starts with 'T').")
                st.stop()
            with st.spinner("Contacting Elliptic API…"):
                try:
                    result  = screen_wallet(api_key.strip(), api_secret.strip(), address.strip())
                    score_f = result.get("risk_score")
                    verdict = ("✅ Clear"          if score_f is not None and float(score_f) < 1
                               else "🟠 Medium Risk" if score_f is not None and float(score_f) < 5
                               else "🔴 High Risk"   if score_f is not None else "❓ Unknown")
                    log_usage(user_email, address.strip(), "single", risk_score=score_f, verdict=verdict)
                    st.success("✅ Screening complete!")
                    render_report(result, address.strip())
                except WalletNotFoundError:
                    log_usage(user_email, address.strip(), "single", verdict="⬜ Not Found")
                    render_not_found(address.strip())
                except requests.HTTPError:
                    pass
                except requests.ConnectionError:
                    st.error("Connection error — check your network.")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")
                    st.exception(e)

    # ══════════════════════════════════════════════════════════════════════════
    # BULK SCAN
    # ══════════════════════════════════════════════════════════════════════════
    else:
        st.markdown("**Upload an Excel (.xlsx) or CSV file.** Column must be named `address`, `wallet`, or `hash`.")
        uploaded = st.file_uploader("Upload file", type=["xlsx","xls","csv"], label_visibility="collapsed")

        if uploaded:
            try:
                if uploaded.name.endswith(".csv"):
                    df_raw = pd.read_csv(uploaded)
                elif uploaded.name.endswith(".xlsx"):
                    df_raw = pd.read_excel(uploaded, engine="openpyxl")
                else:
                    df_raw = pd.read_excel(uploaded, engine="xlrd")
            except ImportError as e:
                missing = "openpyxl" if "openpyxl" in str(e) else "xlrd"
                st.error(f"Missing dependency: `{missing}`. Add to `requirements.txt`.")
                st.stop()
            except Exception as e:
                st.error(f"Could not read file: {e}")
                st.stop()

            col_map  = {c.lower().strip(): c for c in df_raw.columns}
            addr_col = next((col_map[c] for c in ["address","wallet","hash","wallet_address","tron_address"] if c in col_map), None)
            if addr_col is None:
                st.error(f"No address column found. Columns: **{', '.join(df_raw.columns)}**")
                st.stop()

            addresses  = df_raw[addr_col].dropna().astype(str).str.strip().drop_duplicates().tolist()
            extra_cols = [c for c in df_raw.columns if c != addr_col]
            st.info(f"Found **{len(addresses)}** unique wallet address(es).")

            col_btn, col_delay, _ = st.columns([1,1,2])
            with col_btn:
                run_bulk = st.button("🚀 Start Bulk Scan", type="primary", use_container_width=True)
            with col_delay:
                delay = st.number_input("Delay (s)", min_value=0.5, max_value=10.0, value=1.0, step=0.5)

            if run_bulk:
                if not api_key or not api_secret:
                    st.error("Enter API credentials in the sidebar.")
                    st.stop()

                results_rows = []
                prog   = st.progress(0)
                status = st.empty()
                total  = len(addresses)

                for i, addr in enumerate(addresses):
                    status.markdown(f"Scanning {i+1}/{total}: `{addr}`")
                    prog.progress((i+1) / total)

                    orig       = df_raw[df_raw[addr_col].astype(str).str.strip() == addr]
                    extra_vals = {c: orig.iloc[0][c] if not orig.empty else "" for c in extra_cols}

                    if not addr.startswith("T"):
                        verdict = "⚠️ Invalid Address"
                        results_rows.append({addr_col: addr, **extra_vals,
                            "Risk Score":"—","Verdict":verdict,"Source Risk":"—","Dest Risk":"—",
                            "Inflow (USD)":"—","Outflow (USD)":"—","Flagged Entities":"—",
                            "Triggered Rules":"—","Error":"Not a valid Tron address"})
                        log_usage(user_email, addr, "bulk", verdict=verdict)
                        continue

                    try:
                        data    = screen_wallet(api_key.strip(), api_secret.strip(), addr)
                        score   = data.get("risk_score")
                        score_f = float(score) if score is not None else None
                        verdict = ("✅ Clear"          if score_f is not None and score_f < 1
                                   else "🟠 Medium Risk" if score_f is not None and score_f < 5
                                   else "🔴 High Risk"   if score_f is not None else "❓ Unknown")
                        rsd     = data.get("risk_score_detail") or {}
                        bi      = (data.get("blockchain_info") or {}).get("cluster") or {}
                        inflow  = (bi.get("inflow_value")  or {}).get("usd")
                        outflow = (bi.get("outflow_value") or {}).get("usd")
                        contrib = data.get("contributions") or {}
                        flagged = []
                        for side in ["source","destination"]:
                            for c in (contrib.get(side) or []):
                                if not isinstance(c, dict): continue
                                ent = ((c.get("entities") or [{}])[0])
                                cat = ent.get("category","") if isinstance(ent, dict) else ""
                                if any(kw in cat for kw in ["Sanctioned","Blacklist","Gambling","Darknet","Scam","Ransomware"]):
                                    flagged.append(f"{ent.get('name','?')} ({cat})")
                        ev    = data.get("evaluation_detail") or {}
                        rules = list({r.get("rule_name","?") for r in
                                      (ev.get("source") or []) + (ev.get("destination") or [])
                                      if isinstance(r, dict) and r.get("risk_score", 0) > 0})
                        results_rows.append({addr_col: addr, **extra_vals,
                            "Risk Score":  f"{score_f:.4f}" if score_f is not None else "—",
                            "Verdict":     verdict,
                            "Source Risk": f"{float(rsd['source']):.4f}" if rsd.get("source") is not None else "—",
                            "Dest Risk":   f"{float(rsd['destination']):.4f}" if rsd.get("destination") is not None else "—",
                            "Inflow (USD)":  fmt_usd(inflow), "Outflow (USD)": fmt_usd(outflow),
                            "Flagged Entities": "; ".join(set(flagged)) if flagged else "None",
                            "Triggered Rules":  "; ".join(rules) if rules else "None",
                            "Error": ""})
                        log_usage(user_email, addr, "bulk", risk_score=score_f, verdict=verdict)

                    except WalletNotFoundError:
                        verdict = "⬜ Not Found"
                        results_rows.append({addr_col: addr, **extra_vals,
                            "Risk Score":"—","Verdict":verdict,"Source Risk":"—","Dest Risk":"—",
                            "Inflow (USD)":"—","Outflow (USD)":"—","Flagged Entities":"—",
                            "Triggered Rules":"—","Error":"Wallet not on blockchain / empty"})
                        log_usage(user_email, addr, "bulk", verdict=verdict)

                    except Exception as e:
                        verdict = "❌ Error"
                        results_rows.append({addr_col: addr, **extra_vals,
                            "Risk Score":"—","Verdict":verdict,"Source Risk":"—","Dest Risk":"—",
                            "Inflow (USD)":"—","Outflow (USD)":"—","Flagged Entities":"—",
                            "Triggered Rules":"—","Error": str(e)})
                        log_usage(user_email, addr, "bulk", verdict=verdict)

                    if i < total - 1:
                        time.sleep(delay)

                status.empty()
                prog.empty()

                results_df = pd.DataFrame(results_rows)
                st.divider()
                st.markdown("### 📊 Bulk Scan Results")

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Scanned", len(results_df))
                m2.metric("✅ Clear",       (results_df["Verdict"] == "✅ Clear").sum())
                m3.metric("⚠️ Flagged",    results_df["Verdict"].isin(["🟠 Medium Risk","🔴 High Risk"]).sum())
                m4.metric("❌ Errors",      results_df["Verdict"].isin(["❌ Error","⚠️ Invalid Address","⬜ Not Found"]).sum())

                def style_verdict(val):
                    return {"✅ Clear":"color:green;font-weight:600",
                            "🟠 Medium Risk":"color:orange;font-weight:600",
                            "🔴 High Risk":"color:red;font-weight:600"}.get(val,"color:gray")

                st.dataframe(results_df.style.map(style_verdict, subset=["Verdict"]),
                             use_container_width=True, hide_index=True)

                out = io.BytesIO()
                with pd.ExcelWriter(out, engine="openpyxl") as w:
                    results_df.to_excel(w, index=False, sheet_name="Screening Results")
                out.seek(0)
                st.download_button("⬇️ Download Results (.xlsx)", data=out,
                    file_name=f"elliptic_bulk_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True)

if __name__ == "__main__":
    main()
