import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json


# ── Load base KEV data ────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    kev = pd.read_json("Defense_KEV_Entries.json")
    kev["Date Added"] = pd.to_datetime(kev["Date Added"])
    kev["Due Date"]   = pd.to_datetime(kev["Due Date"])
    cvss = pd.read_json("Data_with_Scores.json")
    merged = kev.merge(
        cvss[["CVE ID", "Base", "Impact", "Exploitability"]],
        on="CVE ID", how="left",
    )
    return kev, cvss, merged


# ── Load enriched deep-dive data ─────────────────────────────────────────────
@st.cache_data
def load_enriched():
    df = pd.read_json("CISA_KEV_Defense_TI_Report_Enriched.json")
    df["Date Added"] = pd.to_datetime(df["Date Added"], errors="coerce")
    sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    df["_sev_num"] = df["Severity"].map(sev_order).fillna(0)
    return df


# ── Helper: build CVE hover string capped at 20 ───────────────────────────────
def cve_hover(x):
    ids = sorted(x)
    text = "<br>".join(ids[:20])
    if len(ids) > 20:
        text += f"<br>... and {len(ids) - 20} more"
    return text


# ── CoA lookup tables ─────────────────────────────────────────────────────────
ATTACK_VECTOR_CONTROLS = {
    "Network": {
        "nist_control":   "SI-2 / CM-7",
        "nist_name":      "Flaw Remediation / Least Functionality",
        "control_action": "Apply vendor patch immediately; disable unnecessary network services; restrict inbound access via firewall ACL",
    },
    "Adjacent": {
        "nist_control":   "SC-7 / AC-3",
        "nist_name":      "Boundary Protection / Access Enforcement",
        "control_action": "Segment affected subnet; apply patch within maintenance window; verify VLAN isolation",
    },
    "Local": {
        "nist_control":   "AC-6 / SI-2",
        "nist_name":      "Least Privilege / Flaw Remediation",
        "control_action": "Restrict local user privileges; apply patch; audit local account activity for IOCs",
    },
    "Physical": {
        "nist_control":   "PE-3 / AC-6",
        "nist_name":      "Physical Access Control / Least Privilege",
        "control_action": "Enforce physical access controls; patch device firmware; review device audit logs",
    },
}

SEVERITY_PRIORITY = {
    "Critical": ("P1 — 24 hrs",  "#ef4444"),
    "High":     ("P2 — 72 hrs",  "#f97316"),
    "Medium":   ("P3 — 14 days", "#eab308"),
    "Low":      ("P4 — 30 days", "#34d399"),
}

RANSOMWARE_EXTRA_CONTROL = "RA-5 / IR-4 — Vulnerability Scanning / Incident Handling: Initiate ransomware playbook; isolate if actively exploited; notify CISO"


def build_coa_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, r in df.iterrows():
        cve_id     = r.get("CVE ID", "")
        vuln_name  = r.get("Vulnerability Name", "")
        vendor     = r.get("Vendor / Project", "")
        product    = r.get("Product", "")
        severity   = str(r.get("Severity", ""))
        av_raw     = str(r.get("Attack Vector", "Network"))
        ransomware = r.get("Ransomware Use", "Unknown")
        cisa_dir   = r.get("CISA Directive", "")
        patch      = r.get("Patch Released", "")

        av_key = "Network"
        for k in ATTACK_VECTOR_CONTROLS:
            if k.lower() in av_raw.lower():
                av_key = k
                break

        ctrl      = ATTACK_VECTOR_CONTROLS[av_key]
        pri_label, _ = SEVERITY_PRIORITY.get(severity, ("P4 — 30 days", "#94a3b8"))

        rec_control = ctrl["control_action"]
        nist_ctrl   = ctrl["nist_control"]
        nist_name   = ctrl["nist_name"]

        if ransomware == "Known":
            nist_ctrl   += " / RA-5 / IR-4"
            rec_control  = rec_control + "; " + RANSOMWARE_EXTRA_CONTROL

        rows.append({
            "CVE ID":                  cve_id,
            "Vulnerability Name":      vuln_name,
            "Vendor / Project":        vendor,
            "Product":                 product,
            "Severity":                severity,
            "Threat Indicator":        av_raw,
            "Attack Vector":           av_key,
            "Ransomware Use":          ransomware,
            "NIST SP 800-171 Control": nist_ctrl,
            "Control Name":            nist_name,
            "Recommended Control":     rec_control,
            "Patch Available":         patch,
            "CISA Directive":          cisa_dir,
            "Response Priority":       pri_label,
        })

    return pd.DataFrame(rows)


def render():

    kev_df, cvss_df, merged_df = load_data()
    df_enriched = load_enriched()

    # ── CSS ───────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@400;500;600&display=swap');

    .dash-section-header {
        font-family: 'Space Mono', monospace;
        font-size: 1.6rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.04em;
        margin-bottom: 0.5rem;
    }
    .dash-sub-header {
        font-family: 'Space Mono', monospace;
        font-size: 1rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
    }
    .dash-kpi-card {
        background: rgba(14,165,233,0.06);
        border: 1px solid rgba(56,189,248,0.18);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        text-align: center;
    }
    .dash-kpi-value {
        font-family: 'Space Mono', monospace;
        font-size: 2rem;
        font-weight: 700;
        color: #38bdf8;
        line-height: 1.1;
    }
    .dash-kpi-value-red   { color: #ef4444 !important; }
    .dash-kpi-value-amber { color: #f97316 !important; }
    .dash-kpi-label {
        font-size: 0.72rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        margin-top: 0.3rem;
    }
    .dash-kpi-delta       { font-size: 0.72rem; color: #f97316; margin-top: 0.2rem; }
    .dash-kpi-delta-red   { font-size: 0.72rem; color: #ef4444; margin-top: 0.2rem; }
    .dash-kpi-delta-green { font-size: 0.72rem; color: #34d399; margin-top: 0.2rem; }
    .dash-alert-banner {
        background: rgba(239,68,68,0.06);
        border: 1px solid rgba(239,68,68,0.25);
        border-left: 3px solid #ef4444;
        border-radius: 0 10px 10px 0;
        padding: 0.9rem 1.2rem;
        margin-bottom: 1.2rem;
    }
    .tooltip-icon {
        position: relative;
        display: inline-block;
        cursor: pointer;
        font-size: 0.8rem;
        color: #38bdf8;
        border: 1px solid rgba(56,189,248,0.4);
        border-radius: 50%;
        width: 18px;
        height: 18px;
        text-align: center;
        line-height: 16px;
        font-weight: bold;
    }
    .tooltip-text {
        visibility: hidden;
        width: 320px;
        background-color: #0f172a;
        color: #e2e8f0;
        text-align: left;
        border-radius: 8px;
        padding: 10px;
        position: absolute;
        z-index: 100;
        bottom: 125%;
        left: 50%;
        transform: translateX(-50%);
        border: 1px solid rgba(56,189,248,0.25);
        font-size: 0.75rem;
        line-height: 1.4;
        opacity: 0;
        transition: opacity 0.2s ease-in-out;
    }
    .tooltip-icon:hover .tooltip-text {
        visibility: visible;
        opacity: 1;
    }
    div[data-testid="stDownloadButton"] button {
        background: rgba(14,165,233,0.08) !important;
        border: 1px solid rgba(56,189,248,0.35) !important;
        color: #38bdf8 !important;
        font-family: 'Space Mono', monospace !important;
        font-size: 0.75rem !important;
        font-weight: 700 !important;
        letter-spacing: 0.05em !important;
        border-radius: 8px !important;
        padding: 0.4rem 1rem !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stDownloadButton"] button:hover {
        background: rgba(14,165,233,0.18) !important;
        border-color: #38bdf8 !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def section_header(label, emoji=""):
        prefix = f"{emoji} " if emoji else ""
        st.markdown(f'<div class="dash-section-header">{prefix}{label}</div>', unsafe_allow_html=True)

    def sub_header(label, emoji=""):
        prefix = f"{emoji} " if emoji else ""
        st.markdown(f'<div class="dash-sub-header">{prefix}{label}</div>', unsafe_allow_html=True)

    def chart_header(title, tooltip, key=None):
        st.markdown(f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                <div class="sub-header">{title}</div>
                <div class="tooltip-icon">ⓘ<span class="tooltip-text">{tooltip}</span></div>
            </div>
        """, unsafe_allow_html=True)

    def kpi_card(value, label, delta="", delta_class="dash-kpi-delta", value_class=""):
        v_cls = f"dash-kpi-value {value_class}".strip()
        delta_html = f'<div class="{delta_class}">{delta}</div>' if delta else ""
        st.markdown(
            f'<div class="dash-kpi-card"><div class="{v_cls}">{value}</div>'
            f'<div class="dash-kpi-label">{label}</div>{delta_html}</div>',
            unsafe_allow_html=True,
        )

    def render_export_buttons(df_to_export, export_cols, filename_base="kev_triage", key_suffix=""):
        available_export_cols = [c for c in export_cols if c in df_to_export.columns]
        df_export = df_to_export[available_export_cols].copy()
        for col in df_export.select_dtypes(include=["datetime64[ns]", "datetime64[ns, UTC]"]).columns:
            df_export[col] = df_export[col].dt.strftime("%Y-%m-%d")
        csv_bytes  = df_export.to_csv(index=False).encode("utf-8")
        json_bytes = df_export.to_json(orient="records", indent=2).encode("utf-8")
        st.markdown(
            "<div style='font-family:Space Mono,monospace;font-size:0.72rem;font-weight:700;"
            "color:#64748b;text-transform:uppercase;letter-spacing:0.06em;"
            "margin:0.8rem 0 0.4rem 0;'>⬇️ Export Current View</div>",
            unsafe_allow_html=True,
        )
        exp_col1, exp_col2, _ = st.columns([1, 1, 4])
        with exp_col1:
            st.download_button(
                label="📄 CSV", data=csv_bytes,
                file_name=f"{filename_base}.csv", mime="text/csv",
                key=f"export_csv_{key_suffix}", use_container_width=True,
            )
        with exp_col2:
            st.download_button(
                label="{ } JSON", data=json_bytes,
                file_name=f"{filename_base}.json", mime="application/json",
                key=f"export_json_{key_suffix}", use_container_width=True,
            )

    EXPORT_COLS = [
        "CVE ID", "Vulnerability Name", "Vendor / Project", "Product",
        "Severity", "Ransomware Use", "Date Added", "Due Date",
        "Patch Released", "Attack Vector", "CISA Directive",
        "Defense Relevance", "Recommended Actions",
    ]

    SEVERITY_COLORS = {
        "Critical": "#E24B4A",
        "High":     "#EF9F27",
        "Medium":   "#378ADD",
        "Low":      "#1D9E75",
    }

    # ── Page header ───────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🏩 Operational Triage Dashboard</div>', unsafe_allow_html=True)
    st.caption(
        "100 vulnerabilities curated from CISA's Known Exploited Vulnerabilities catalog — "
        "prioritized by Emergency Directives, active exploitation, and DoD/federal prevalence."
    )

    # ═════════════════════════════════════════════════════════════════════════
    # TOP-LEVEL TABS
    # ═════════════════════════════════════════════════════════════════════════
    tab_deepdive, tab_coa = st.tabs([
        "🔍 CVE Deep Dive",
        "🗺️ Course-of-Action Mapping",
    ])

    # ═════════════════════════════════════════════════════════════════════════
    # TAB 1 — CVE DEEP DIVE
    # ═════════════════════════════════════════════════════════════════════════
    with tab_deepdive:

        st.markdown('<div class="sub-header">🔍 CVE Deep Dive — Interactive Vulnerability Explorer</div>', unsafe_allow_html=True)
        st.caption(
            "Navigate by Vendor → Product → CVE ID. "
            "Charts and metrics update dynamically as you refine your selection."
        )

        ctrl_a, _ = st.columns([3, 1])
        with ctrl_a:
            analytic_view = st.selectbox(
                "📊 Analytic View",
                [
                    "CVE Deep Dive",
                    "Vendor Risk Profile",
                    "Attack Vector Breakdown",
                    "Ransomware Exposure",
                    "Timeline — CVEs Added Over Time",
                ],
                help="Choose the type of analysis to display in the chart panel below.",
            )

        st.markdown(
            "<div style='font-family:Space Mono,monospace;font-size:0.75rem;font-weight:700;"
            "color:#64748b;text-transform:uppercase;letter-spacing:0.06em;"
            "margin:0.6rem 0 0.3rem 0;'>🔎 Step-by-Step CVE Selection</div>",
            unsafe_allow_html=True,
        )
        sel_col1, sel_col2, sel_col3 = st.columns(3)

        with sel_col1:
            vendors_available = sorted(df_enriched["Vendor / Project"].dropna().unique())
            selected_vendor = st.selectbox(
                "① Select Vendor",
                ["— All Vendors —"] + vendors_available,
                key="t2_vendor",
            )

        df_vendor = (
            df_enriched if selected_vendor == "— All Vendors —"
            else df_enriched[df_enriched["Vendor / Project"] == selected_vendor]
        )

        with sel_col2:
            products_available = sorted(df_vendor["Product"].dropna().unique())
            selected_product = st.selectbox(
                "② Select Product",
                ["— All Products —"] + products_available,
                key="t2_product",
            )

        df_product = (
            df_vendor if selected_product == "— All Products —"
            else df_vendor[df_vendor["Product"] == selected_product]
        )

        with sel_col3:
            cves_available = sorted(df_product["CVE ID"].dropna().unique())
            selected_cve = st.selectbox(
                "③ Select CVE ID",
                ["— Select a CVE —"] + cves_available,
                key="t2_cve",
                help="Populates the full deep-dive panel below.",
            )

        sev_col, topn_col = st.columns([3, 1])
        with sev_col:
            t2_severity_filter = st.multiselect(
                "Filter chart by Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"],
                key="t2_sev",
            )
        with topn_col:
            n_available = max(1, len(df_product))
            if n_available <= 1:
                top_n = n_available
                st.metric("CVEs Available", top_n)
            else:
                top_n = st.slider(
                    "Top-N CVEs",
                    min_value=1,
                    max_value=min(50, n_available),
                    value=min(10, n_available),
                    step=1,
                    key="t2_topn",
                    help="Limits chart to the top N highest-severity CVEs.",
                )

        df_chart = (
            df_product[df_product["Severity"].isin(t2_severity_filter)]
            if t2_severity_filter else df_product
        )
        df_chart = df_chart.sort_values("_sev_num", ascending=False).head(top_n)

        st.markdown("---")

        m1, m2, m3, m4, m5 = st.columns(5)
        total_filtered = len(df_product)
        t2_critical    = len(df_product[df_product["Severity"] == "Critical"])
        t2_ransomware  = len(df_product[df_product["Ransomware Use"] == "Known"])
        t2_vendors     = df_product["Vendor / Project"].nunique()
        t2_high_crit   = len(df_product[df_product["Severity"].isin(["Critical", "High"])])

        with m1:
            st.metric("CVEs in View", total_filtered)
        with m2:
            pct = round(t2_critical / total_filtered * 100) if total_filtered else 0
            st.metric("Critical Severity", t2_critical, delta=f"{pct}%", delta_color="inverse")
        with m3:
            st.metric("High + Critical", t2_high_crit)
        with m4:
            pct_r = round(t2_ransomware / total_filtered * 100) if total_filtered else 0
            st.metric("Ransomware-Linked", t2_ransomware, delta=f"{pct_r}%", delta_color="inverse")
        with m5:
            st.metric("Vendors Shown", t2_vendors)

        st.markdown("---")

        # ── CVE Detail panel ──────────────────────────────────────────────
        if selected_cve != "— Select a CVE —":

            cve_row = df_enriched[df_enriched["CVE ID"] == selected_cve]
            if cve_row.empty:
                st.warning(f"CVE {selected_cve} not found in dataset.")
            else:
                r = cve_row.iloc[0]

                sev_badge_colors = {
                    "Critical": ("#ff6b6b", "rgba(239,68,68,0.12)"),
                    "High":     ("#f97316", "rgba(249,115,22,0.12)"),
                    "Medium":   ("#38bdf8", "rgba(56,189,248,0.12)"),
                    "Low":      ("#34d399", "rgba(52,211,153,0.12)"),
                }
                sev = str(r.get("Severity", "Unknown"))
                badge_fg, badge_bg = sev_badge_colors.get(sev, ("#94a3b8", "rgba(148,163,184,0.12)"))
                ransomware_badge = (
                    "<span style='background:rgba(239,68,68,0.15);color:#ef4444;"
                    "padding:4px 12px;border-radius:6px;font-size:12px;font-weight:600;"
                    "border:1px solid rgba(239,68,68,0.3);'>🔴 Ransomware-Linked</span>"
                    if r.get("Ransomware Use") == "Known" else ""
                )

                st.markdown(
                    f"""
                    <div style="background:rgba(14,165,233,0.04);border:1px solid rgba(56,189,248,0.15);
                                border-radius:12px;padding:1.2rem 1.5rem;margin-bottom:1rem;">
                        <div style="display:flex;align-items:center;gap:14px;margin-bottom:8px;flex-wrap:wrap;">
                            <span style="font-size:20px;font-weight:700;font-family:'Space Mono',monospace;
                                            color:#38bdf8;">{r["CVE ID"]} </span>
                            <span style="background:{badge_bg};color:{badge_fg};padding:4px 14px;
                                            border-radius:6px;font-size:13px;font-weight:600;
                                            border:1px solid {badge_fg}33;">{sev} </span> {ransomware_badge}
                        </div>
                        <div style="font-size:16px;font-weight:600;color:#e2e8f0;margin-bottom:4px;">
                            {r.get("Vulnerability Name", "")}
                        </div>
                        <div style="font-size:13px;color:#64748b;">
                            {r.get("Vendor / Project", "")} &mdash; {r.get("Product", "")}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                def detail_row(label, value):
                    if pd.isna(value) or str(value).strip() in ("", "nan", "—", "NaN"):
                        return ""
                    return (
                        f"<tr>"
                        f"<td style='color:#64748b;padding:6px 14px 6px 0;white-space:nowrap;"
                        f"vertical-align:top;font-size:12px;text-transform:uppercase;"
                        f"letter-spacing:0.04em;font-weight:600;'>{label}</td>"
                        f"<td style='padding:6px 0;font-size:13px;color:#cbd5e1;"
                        f"line-height:1.5;'>{value}</td>"
                        f"</tr>"
                    )

                col_left, col_right = st.columns(2)

                with col_left:
                    sub_header("Technical Details", "🔬")
                    html = "<table style='width:100%;border-collapse:collapse;'>"
                    html += detail_row("Component",         r.get("Component", ""))
                    html += detail_row("CWE",               r.get("Weakness / CWE", r.get("CWEs", "")))
                    html += detail_row("Attack Vector",     r.get("Attack Vector", ""))
                    html += detail_row("CIA Impact",        r.get("CIA Impact", ""))
                    html += detail_row("Affected Versions", r.get("Affected Versions", ""))
                    html += detail_row("Platforms",         r.get("Platforms Affected", ""))
                    html += detail_row("Root Cause",        r.get("Root Cause", ""))
                    html += detail_row("Exploit Primitive", r.get("Exploit Primitive", ""))
                    html += detail_row("Prerequisite",      r.get("Attack Prerequisite", ""))
                    html += "</table>"
                    st.markdown(html, unsafe_allow_html=True)

                with col_right:
                    sub_header("Government & Threat Context", "🏛️")
                    html2 = "<table style='width:100%;border-collapse:collapse;'>"
                    html2 += detail_row("CISA Directive",         r.get("CISA Directive", ""))
                    html2 += detail_row("Date Added to KEV",      str(r.get("Date Added", ""))[:10])
                    html2 += detail_row("Due Date",               str(r.get("Due Date", ""))[:10])
                    html2 += detail_row("Patch Released",         r.get("Patch Released", ""))
                    html2 += detail_row("Defense Relevance",      r.get("Defense Relevance", ""))
                    html2 += detail_row("Gov / Defense Impact",   r.get("Defense / Gov Impact", ""))
                    html2 += detail_row("Threat Actor Relevance", r.get("Threat Actor Relevance", ""))
                    html2 += detail_row("Related CVEs",           r.get("Related CVEs", ""))
                    html2 += detail_row("Reported By",            r.get("Reported By", ""))
                    html2 += "</table>"
                    st.markdown(html2, unsafe_allow_html=True)

                chain = str(r.get("Full Attack Chain", "")).strip()
                if chain and chain not in ("", "nan"):
                    st.markdown("<br>", unsafe_allow_html=True)
                    sub_header("Full Attack Chain", "⛓️")
                    steps = [s.strip() for s in chain.split("  ") if s.strip()]
                    step_colors = ["#ef4444", "#f97316", "#eab308", "#0ea5e9", "#22c55e"]
                    cols = st.columns(min(len(steps), 5))
                    for i, (step, col) in enumerate(zip(steps, cols)):
                        text = ")".join(step.split(")")[1:]).strip() if ")" in step else step
                        c = step_colors[i % len(step_colors)]
                        col.markdown(
                            f"""<div style="background:{c}18;border-left:3px solid {c};
                                            padding:10px 12px;border-radius:4px;
                                            font-size:12px;color:#cbd5e1;min-height:90px;
                                            line-height:1.5;">
                                    <div style="font-weight:700;color:{c};margin-bottom:4px;">Step {i+1}</div>
                                    {text}
                                </div>""",
                            unsafe_allow_html=True,
                        )

                actions = str(r.get("Recommended Actions", "")).strip()
                if actions and actions not in ("", "nan"):
                    st.markdown("<br>", unsafe_allow_html=True)
                    sub_header("Recommended Actions", "✅")
                    action_list = [a.strip() for a in actions.split("  ") if a.strip()]
                    for action in action_list:
                        num_part  = action.split(")")[0] if ")" in action else ""
                        text_part = ")".join(action.split(")")[1:]).strip() if ")" in action else action
                        st.markdown(
                            f"""<div style="display:flex;gap:10px;align-items:flex-start;
                                            padding:7px 0;border-bottom:1px solid #1e293b;">
                                    <span style="background:rgba(52,211,153,0.12);color:#34d399;
                                                    padding:2px 8px;border-radius:4px;
                                                    font-size:11px;font-weight:700;
                                                    white-space:nowrap;border:1px solid #34d39933;">
                                        {num_part}
                                    </span>
                                    <span style="font-size:13px;color:#cbd5e1;">{text_part}</span>
                                </div>""",
                            unsafe_allow_html=True,
                        )

                nvd        = str(r.get("NVD Reference", "")).strip()
                vendor_url = str(r.get("Vendor Advisory URL", "")).strip()
                if nvd not in ("", "nan") or vendor_url not in ("", "nan"):
                    st.markdown("<br>", unsafe_allow_html=True)
                    sub_header("References", "🔗")
                    ref_cols = st.columns(2)
                    if nvd not in ("", "nan"):
                        ref_cols[0].markdown(f"[📄 NVD Entry — {r['CVE ID']}]({nvd})")
                    if vendor_url not in ("", "nan"):
                        ref_cols[1].markdown(f"[🏢 Vendor Advisory]({vendor_url})")

                st.markdown("---")
                render_export_buttons(
                    cve_row, EXPORT_COLS,
                    filename_base=f"cve_{selected_cve.replace('-', '_')}",
                    key_suffix=f"cve_detail_{selected_cve}",
                )

        else:
            st.info(
                "👆 Select a **Vendor**, **Product**, then **CVE ID** above to load the full deep-dive: "
                "root cause, exploit chain, government impact, threat actor relevance, and remediation steps."
            )
            if not df_chart.empty:
                chart_header(
                    "📋 CVEs in Current Filter",
                    "This table lists the CVEs that match the current Vendor/Product selection.",
                    "info_cve_table",
                )
                display_cols = [
                    "CVE ID", "Vulnerability Name", "Vendor / Project", "Product",
                    "Severity", "Ransomware Use", "Date Added", "Patch Released",
                ]
                available_cols = [c for c in display_cols if c in df_chart.columns]
                st.dataframe(
                    df_chart[available_cols].reset_index(drop=True),
                    use_container_width=True, hide_index=True, height=320,
                )
                render_export_buttons(
                    df_chart, EXPORT_COLS,
                    filename_base="kev_triage_filtered",
                    key_suffix="table_view",
                )

        # ── Chart ─────────────────────────────────────────────────────────
        st.markdown("---")
        chart_header(
            "📊 Vulnerability Chart",
            "The topic of this visual is based on the Analytical view you choose, while the data is based on the filters above.",
            "info_chart_explanation",
        )

        if analytic_view == "CVE Deep Dive":
            if df_chart.empty:
                st.info("No CVEs match the current filter combination.")
            else:
                fig = px.bar(
                    df_chart, x="CVE ID", y="_sev_num", color="Severity",
                    color_discrete_map=SEVERITY_COLORS,
                    hover_data=["Vulnerability Name", "Product", "Vendor / Project",
                                "Ransomware Use", "Patch Released"],
                    labels={"_sev_num": "Severity Score", "CVE ID": "CVE"},
                    title=f"Top-{top_n} CVEs by Severity — {selected_vendor} / {selected_product}",
                    template="plotly_dark", height=400,
                )
                fig.update_layout(
                    xaxis_tickangle=-45,
                    yaxis=dict(tickvals=[1, 2, 3, 4], ticktext=["Low", "Medium", "High", "Critical"]),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#94a3b8"),
                )
                for _, r_row in df_chart.iterrows():
                    if r_row.get("Ransomware Use") == "Known":
                        fig.add_annotation(
                            x=r_row["CVE ID"], y=r_row["_sev_num"] + 0.15,
                            text="🔴 Ransomware", showarrow=False,
                            font=dict(size=9, color="#E24B4A"),
                        )
                st.plotly_chart(fig, use_container_width=True)
                render_export_buttons(
                    df_chart, EXPORT_COLS,
                    filename_base=f"kev_top{top_n}_severity",
                    key_suffix="cve_deep_dive_chart",
                )

        elif analytic_view == "Vendor Risk Profile":
            vendor_summary = (
                df_enriched.groupby("Vendor / Project")
                .agg(
                    Critical=("Severity", lambda x: (x == "Critical").sum()),
                    Ransomware=("Ransomware Use", lambda x: (x == "Known").sum()),
                    CVEs=("CVE ID", cve_hover),
                )
                .reset_index()
                .sort_values("Critical", ascending=False)
                .head(top_n)
            )
            fig = px.bar(
                vendor_summary, x="Vendor / Project", y=["Critical", "Ransomware"],
                barmode="group",
                color_discrete_map={"Critical": "#E24B4A", "Ransomware": "#EF9F27"},
                title=f"Top-{top_n} Vendors — Critical CVEs vs Ransomware-Linked CVEs",
                template="plotly_dark", height=420,
            )
            fig.update_layout(
                xaxis_tickangle=-30,
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
            )
            st.plotly_chart(fig, use_container_width=True)
            render_export_buttons(
                vendor_summary, ["Vendor / Project", "Critical", "Ransomware"],
                filename_base=f"vendor_risk_profile_top{top_n}",
                key_suffix="vendor_risk",
            )

        elif analytic_view == "Attack Vector Breakdown":
            if df_chart.empty:
                st.info("No data for current selection.")
            elif "Attack Vector" not in df_chart.columns:
                st.info("Attack Vector data not available.")
            else:
                df_av = df_chart.copy()
                df_av["_av_short"] = df_av["Attack Vector"].str.split("/").str[0].str.strip()
                av_counts = (
                    df_av.groupby("_av_short")
                    .agg(Count=("CVE ID", "count"), CVEs=("CVE ID", cve_hover))
                    .reset_index()
                    .rename(columns={"_av_short": "Attack Vector"})
                )
                fig = px.pie(
                    av_counts, names="Attack Vector", values="Count",
                    title=f"Attack Vector Distribution — {selected_vendor} / {selected_product}",
                    hole=0.4,
                    color_discrete_sequence=["#E24B4A", "#EF9F27", "#378ADD", "#1D9E75"],
                    template="plotly_dark", height=400, custom_data=["CVEs"],
                )
                fig.update_traces(
                    hovertemplate="<b>%{label}</b><br>Count: %{value}<br><br>CVEs:<br>%{customdata[0]}<extra></extra>",
                )
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#94a3b8"))
                st.plotly_chart(fig, use_container_width=True)
                render_export_buttons(
                    df_chart, EXPORT_COLS,
                    filename_base="attack_vector_breakdown",
                    key_suffix="av_breakdown",
                )

        elif analytic_view == "Ransomware Exposure":
            ransom_data = (
                df_enriched.groupby(["Vendor / Project", "Ransomware Use"])
                .agg(Count=("CVE ID", "count"), CVEs=("CVE ID", cve_hover))
                .reset_index()
            )
            ransom_known = (
                ransom_data[ransom_data["Ransomware Use"] == "Known"]
                .sort_values("Count", ascending=False)
                .head(top_n)
            )
            if ransom_known.empty:
                st.info("No ransomware-linked CVEs found.")
            else:
                fig = px.bar(
                    ransom_known, x="Vendor / Project", y="Count",
                    color_discrete_sequence=["#E24B4A"],
                    title=f"Top-{top_n} Vendors by Ransomware-Linked CVE Count",
                    template="plotly_dark", height=400, text="Count", custom_data=["CVEs"],
                )
                fig.update_traces(
                    textposition="outside",
                    hovertemplate="<b>%{x}</b><br>Count: %{y}<br><br>CVEs:<br>%{customdata[0]}<extra></extra>",
                )
                fig.update_layout(
                    xaxis_tickangle=-30,
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#94a3b8"),
                )
                st.plotly_chart(fig, use_container_width=True)
                render_export_buttons(
                    ransom_known, ["Vendor / Project", "Ransomware Use", "Count"],
                    filename_base=f"ransomware_exposure_top{top_n}",
                    key_suffix="ransomware",
                )

        elif analytic_view == "Timeline — CVEs Added Over Time":
            df_time = df_enriched.dropna(subset=["Date Added"]).copy()
            df_time["Month"] = df_time["Date Added"].dt.to_period("M").dt.to_timestamp()
            timeline = (
                df_time.groupby(["Month", "Severity"])
                .agg(Count=("CVE ID", "count"), CVEs=("CVE ID", cve_hover))
                .reset_index()
            )
            fig = px.area(
                timeline, x="Month", y="Count", color="Severity",
                color_discrete_map=SEVERITY_COLORS,
                title="CVEs Added to KEV by Month and Severity",
                template="plotly_dark", height=420, custom_data=["CVEs"],
            )
            fig.update_traces(
                hovertemplate="<b>%{x}</b> — %{fullData.name}<br>Count: %{y}<br><br>CVEs:<br>%{customdata[0]}<extra></extra>",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
            )
            st.plotly_chart(fig, use_container_width=True)
            timeline_export = df_time[["CVE ID", "Vulnerability Name", "Vendor / Project",
                                       "Product", "Severity", "Date Added", "Ransomware Use",
                                       "Patch Released"]].copy()
            render_export_buttons(
                timeline_export, list(timeline_export.columns),
                filename_base="kev_timeline", key_suffix="timeline",
            )

    # ═════════════════════════════════════════════════════════════════════════
    # TAB 2 — COURSE-OF-ACTION MAPPING
    # ═════════════════════════════════════════════════════════════════════════
    with tab_coa:
         
        st.markdown("""
        <div class="sub-header">🗺️ IoC → Recommended Control Mapping</div>
        <div style="font-size:0.82rem;color:#64748b;margin-bottom:1.2rem;">
            Each CVE's threat indicator (attack vector + ransomware status) is mapped to a
            NIST SP 800-171 control and a concrete recommended action. Filter and export for
            use in POAMs, incident response playbooks, or compliance reporting.
        </div>
        """, unsafe_allow_html=True)

        # ── CoA filters ───────────────────────────────────────────────────
        coa_f1, coa_f2, coa_f3, coa_f4 = st.columns(4)

        with coa_f1:
            coa_sev = st.multiselect(
                "Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"],
                key="coa_sev",
            )
        with coa_f2:
            coa_av = st.multiselect(
                "Attack Vector",
                options=["Network", "Adjacent", "Local", "Physical"],
                default=["Network", "Adjacent"],
                key="coa_av",
            )
        with coa_f3:
            coa_ransom = st.selectbox(
                "Ransomware Use",
                options=["All", "Known", "Unknown"],
                key="coa_ransom",
            )
        with coa_f4:
            coa_vendor_opts = ["All"] + sorted(df_enriched["Vendor / Project"].dropna().unique().tolist())
            coa_vendor = st.selectbox(
                "Vendor / Project",
                options=coa_vendor_opts,
                key="coa_vendor",
            )

        # Build and filter CoA table
        coa_df = build_coa_table(df_enriched)

        if coa_sev:
            coa_df = coa_df[coa_df["Severity"].isin(coa_sev)]
        if coa_av:
            coa_df = coa_df[coa_df["Attack Vector"].isin(coa_av)]
        if coa_ransom != "All":
            coa_df = coa_df[coa_df["Ransomware Use"] == coa_ransom]
        if coa_vendor != "All":
            coa_df = coa_df[coa_df["Vendor / Project"] == coa_vendor]

        # ── CoA KPI strip ─────────────────────────────────────────────────
        ck1, ck2, ck3, ck4 = st.columns(4)
        with ck1:
            st.metric("CVEs Mapped", len(coa_df))
        with ck2:
            st.metric("P1 / P2 Actions", len(coa_df[coa_df["Response Priority"].str.startswith(("P1", "P2"))]) if not coa_df.empty else 0)
        with ck3:
            st.metric("Ransomware-Linked", len(coa_df[coa_df["Ransomware Use"] == "Known"]) if not coa_df.empty else 0)
        with ck4:
            st.metric("Unique NIST Controls", coa_df["NIST SP 800-171 Control"].nunique() if not coa_df.empty else 0)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Control mapping legend ─────────────────────────────────────────
        with st.expander("ℹ️ Control Mapping Legend — Attack Vector → NIST SP 800-171", expanded=False):
            leg_cols = st.columns(2)
            for i, (av, data) in enumerate(ATTACK_VECTOR_CONTROLS.items()):
                col = leg_cols[i % 2]
                col.markdown(f"""
                <div style="background:rgba(14,165,233,0.04);border:1px solid rgba(56,189,248,0.12);
                            border-left:3px solid #38bdf8;border-radius:0 8px 8px 0;
                            padding:0.75rem 1rem;margin:0.3rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;font-weight:700;
                                color:#38bdf8;margin-bottom:0.3rem;">{av} Attack Vector</div>
                    <div style="font-size:0.75rem;color:#f97316;font-weight:600;margin-bottom:0.2rem;">
                        {data['nist_control']} — {data['nist_name']}
                    </div>
                    <div style="font-size:0.76rem;color:#94a3b8;line-height:1.4;">
                        {data['control_action']}
                    </div>
                </div>""", unsafe_allow_html=True)
            st.markdown(f"""
            <div style="background:rgba(239,68,68,0.04);border:1px solid rgba(239,68,68,0.15);
                        border-left:3px solid #ef4444;border-radius:0 8px 8px 0;
                        padding:0.75rem 1rem;margin:0.3rem 0;">
                <div style="font-family:'Space Mono',monospace;font-size:0.78rem;font-weight:700;
                            color:#ef4444;margin-bottom:0.3rem;">🔴 Ransomware-Linked — Additional Control</div>
                <div style="font-size:0.76rem;color:#94a3b8;line-height:1.4;">{RANSOMWARE_EXTRA_CONTROL}</div>
            </div>""", unsafe_allow_html=True)

        # ── CoA table ─────────────────────────────────────────────────────
        if coa_df.empty:
            st.info("No CVEs match the current CoA filter combination.")
        else:
            display_coa_cols = [
                "CVE ID", "Vendor / Project", "Product", "Severity",
                "Attack Vector", "Ransomware Use",
                "NIST SP 800-171 Control", "Control Name",
                "Recommended Control", "Response Priority", "Patch Available",
            ]
            available_coa_cols = [c for c in display_coa_cols if c in coa_df.columns]

            pri_color_map = {
                "P1 — 24 hrs":  "#ef4444",
                "P2 — 72 hrs":  "#f97316",
                "P3 — 14 days": "#eab308",
                "P4 — 30 days": "#34d399",
            }

            def style_priority(val):
                return f"color: {pri_color_map.get(val, '#94a3b8')}; font-weight: 700;"

            def style_severity(val):
                colors = {"Critical": "#ef4444", "High": "#f97316",
                          "Medium": "#38bdf8", "Low": "#34d399"}
                return f"color: {colors.get(val, '#94a3b8')}; font-weight: 600;"

            styled = (
                coa_df[available_coa_cols]
                .reset_index(drop=True)
                .style
                .applymap(style_priority, subset=["Response Priority"])
                .applymap(style_severity, subset=["Severity"])
            )

            st.dataframe(styled, use_container_width=True, hide_index=True, height=420)

            coa_export_cols = [
                "CVE ID", "Vulnerability Name", "Vendor / Project", "Product",
                "Severity", "Threat Indicator", "Attack Vector", "Ransomware Use",
                "NIST SP 800-171 Control", "Control Name", "Recommended Control",
                "Response Priority", "Patch Available", "CISA Directive",
            ]
            render_export_buttons(
                coa_df, coa_export_cols,
                filename_base="coa_mapping",
                key_suffix="coa_main",
            )