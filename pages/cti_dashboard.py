import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


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

    .insight-sub {
        font-family: 'Space Mono', monospace;
        font-size: 1rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
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
    </style>
    """, unsafe_allow_html=True)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def section_header(label, emoji=""):
        prefix = f"{emoji} " if emoji else ""
        st.markdown(
            f'<div class="dash-section-header">{prefix}{label}</div>',
            unsafe_allow_html=True,
        )

    def sub_header(label, emoji=""):
        prefix = f"{emoji} " if emoji else ""
        st.markdown(
            f'<div class="dash-sub-header">{prefix}{label}</div>',
            unsafe_allow_html=True,
        )

    def chart_header(title, tooltip, key=None):
        st.markdown(f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                <div class="insight-sub">{title}</div>
                <div class="tooltip-icon">
                    ⓘ<span class="tooltip-text">{tooltip}</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    def kpi_card(value, label, delta="", delta_class="dash-kpi-delta", value_class=""):
        v_cls = f"dash-kpi-value {value_class}".strip()
        delta_html = f'<div class="{delta_class}">{delta}</div>' if delta else ""
        st.markdown(
            f'<div class="dash-kpi-card">'
            f'<div class="{v_cls}">{value}</div>'
            f'<div class="dash-kpi-label">{label}</div>'
            f'{delta_html}'
            f'</div>',
            unsafe_allow_html=True,
        )

    def ref_card(label, url):
        st.markdown(f"""
        <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                    padding:0.7rem 1rem;margin:0.4rem 0;">
            <div style="font-family:'Space Mono',monospace;font-size:0.78rem;
                         color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
            <a href="{url}" target="_blank"
               style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
        </div>""", unsafe_allow_html=True)

    # ── Page header ───────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🛡️ CTI Dashboard - KEV Analysis</div>', unsafe_allow_html=True)
    st.caption(
        "100 vulnerabilities curated from CISA's Known Exploited Vulnerabilities catalog — "
        "prioritized by Emergency Directives, active exploitation, and DoD/federal prevalence."
    )

    # tab1 = st.tabs(["📊 KEV Analysis", "🕵️ CVE Deep Dive"])

    # ── Filters ───────────────────────────────────────────────────────────
    sub_header("Filters", "🔧")
    f1, f2, f3, f4 = st.columns([2, 2, 2, 2])

    with f1:
        sev_filter = st.multiselect(
            "Severity",
            options=["Critical", "High"],
            default=["Critical", "High"],
        )
    with f2:
        vendor_opts = ["All"] + sorted(kev_df["Vendor / Project"].dropna().unique().tolist())
        vendor_filter = st.selectbox("Vendor / Project", options=vendor_opts)
    with f3:
        ransomware_filter = st.selectbox("Ransomware Use", ["All", "Known", "Unknown"])
    with f4:
        directive_opts = ["All"] + sorted(kev_df["CISA Directive"].dropna().unique().tolist())
        directive_filter = st.selectbox("CISA Directive", options=directive_opts)

    # Apply filters
    filt = merged_df.copy()
    if sev_filter:
        filt = filt[filt["Severity"].isin(sev_filter)]
    if vendor_filter != "All":
        filt = filt[filt["Vendor / Project"] == vendor_filter]
    if ransomware_filter != "All":
        filt = filt[filt["Ransomware Use"] == ransomware_filter]
    if directive_filter != "All":
        filt = filt[filt["CISA Directive"] == directive_filter]

    st.divider()

    # ── KPIs ──────────────────────────────────────────────────────────────
    sub_header("Key Intelligence Metrics", "📈")
    k1, k2, k3, k4, k5 = st.columns(5)

    total          = len(filt)
    critical_count = len(filt[filt["Severity"] == "Critical"])
    ransomware_cnt = len(filt[filt["Ransomware Use"] == "Known"])
    vendors_cnt    = filt["Vendor / Project"].nunique()
    cvss_vals      = filt["Base"].dropna()
    avg_cvss_val   = f"{cvss_vals.mean():.1f}" if not cvss_vals.empty else "N/A"

    with k1:
        kpi_card(total, "Filtered CVE Entries", "of 100 curated total")
    with k2:
        kpi_card(critical_count, "Critical Severity",
                    "Immediate patch priority", "dash-kpi-delta-red", "dash-kpi-value-red")
    with k3:
        kpi_card(ransomware_cnt, "Ransomware-Linked",
                    "⚠ Confirmed active use", "dash-kpi-delta-red", "dash-kpi-value-amber")
    with k4:
        kpi_card(vendors_cnt, "Unique Vendors", "Across filtered set")
    with k5:
        kpi_card(avg_cvss_val, "Avg CVSS Base Score",
                    "High / Critical range", "dash-kpi-delta-red", "dash-kpi-value-red")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts row 1 ──────────────────────────────────────────────────────
    c1, c2 = st.columns(2)

    with c1:
        chart_header("📊 CVE Additions by Month",
            "This bar graph shows the number of CVEs added to the KEV catalog each month based on the 'Date Added' field. Use this to identify trends in when vulnerabilities are being added, such as spikes that may correlate with major vulnerability disclosures or active exploitation campaigns.",
            "info_cve_additions")

        monthly = (
            filt.groupby(filt["Date Added"].dt.to_period("M"))
            .agg(Count=("CVE ID", "count"), CVEs=("CVE ID", cve_hover))
            .reset_index()
        )
        monthly["Month"] = monthly["Date Added"].astype(str)

        fig_m = px.bar(
            monthly, x="Month", y="Count", text="Count",
            color="Count",
            color_continuous_scale=["#1e3a5f", "#0ea5e9", "#ef4444"],
            template="plotly_dark",
            custom_data=["CVEs"],
        )
        fig_m.update_traces(
            textposition="outside",
            hovertemplate="<b>%{x}</b><br>Count: %{y}<br><br>CVEs:<br>%{customdata[0]}<extra></extra>",
        )
        fig_m.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8", size=10),
            margin=dict(l=0, r=0, t=10, b=0),
            coloraxis_showscale=False,
            xaxis=dict(gridcolor="#1e3a5f", tickangle=-45),
            yaxis=dict(gridcolor="#1e3a5f"),
            height=320,
        )
        st.plotly_chart(fig_m, use_container_width=True)

    with c2:
        chart_header("📊 Top Vendors by CVE Count",
            "This bar graph shows the top vendors or projects with the most CVEs in the current filtered dataset. Use this to quickly identify which vendors have the highest number of vulnerabilities that meet your filter criteria, which can help prioritize patching and risk management efforts.",
            "info_top_vendors")

        vc = (
            filt.groupby("Vendor / Project")
            .agg(Count=("CVE ID", "count"), CVEs=("CVE ID", cve_hover))
            .reset_index()
            .sort_values("Count", ascending=False)
            .head(12)
            .rename(columns={"Vendor / Project": "Vendor", "Count": "CVE Count"})
        )

        fig_v = px.bar(
            vc.sort_values("CVE Count", ascending=True),
            x="CVE Count", y="Vendor", orientation="h",
            color="CVE Count", text="CVE Count",
            color_continuous_scale=["#1e3a5f", "#ef4444"],
            template="plotly_dark",
            custom_data=["CVEs"],
        )
        fig_v.update_traces(
            textposition="outside",
            hovertemplate="<b>%{y}</b><br>Count: %{x}<br><br>CVEs:<br>%{customdata[0]}<extra></extra>",
        )
        fig_v.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8", size=10),
            margin=dict(l=0, r=20, t=10, b=0),
            coloraxis_showscale=False,
            xaxis=dict(gridcolor="#1e3a5f"),
            yaxis=dict(gridcolor="#1e3a5f"),
            height=380,
        )
        st.plotly_chart(fig_v, use_container_width=True)

    # ── Charts row 2 ──────────────────────────────────────────────────────
    c3, c4 = st.columns(2)

    with c3:
        chart_header("📊 CVSS Score Distribution",
            "This histogram shows the distribution of CVSS base scores for CVEs in the current filtered dataset. Use this to understand the severity landscape of the vulnerabilities that meet your filter criteria.",
            "info_cvss_distribution")
        if not cvss_vals.empty:
            fig_c = px.histogram(
                filt.dropna(subset=["Base"]), x="Base", nbins=15,
                color_discrete_sequence=["#0ea5e9"],
                template="plotly_dark",
                labels={"Base": "CVSS Base Score"},
            )
            fig_c.add_vline(
                x=cvss_vals.mean(), line_dash="dash", line_color="#ef4444",
                annotation_text=f"Mean: {cvss_vals.mean():.1f}",
                annotation_font_color="#ef4444",
            )
            fig_c.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8", size=11),
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(gridcolor="#1e3a5f"),
                yaxis=dict(gridcolor="#1e3a5f"),
            )
            st.plotly_chart(fig_c, use_container_width=True)
        else:
            st.info("No CVSS data available for current filter selection.")

    with c4:
        chart_header("📊 Severity vs Ransomware Breakdown",
            "This grouped bar chart shows the count of CVEs by severity level, broken down by whether they are known to be used in ransomware attacks or not. Use this to identify if there are more high-severity CVEs that are actively being exploited by ransomware, which can help prioritize patching efforts.",
            "info_severity_ransomware")

        # Fill NaN ransomware values so they show up as a group
        filt_b = filt.copy()
        filt_b["Ransomware Use"] = filt_b["Ransomware Use"].fillna("Unknown")

        breakdown = (
            filt_b.groupby(["Severity", "Ransomware Use"])
            .agg(Count=("CVE ID", "count"), CVEs=("CVE ID", cve_hover))
            .reset_index()
        )

        fig_b = px.bar(
            breakdown, x="Severity", y="Count", color="Ransomware Use",
            barmode="group", template="plotly_dark",
            color_discrete_map={"Known": "#ef4444", "Unknown": "#3b82f6"},
            custom_data=["CVEs"],
        )
        fig_b.update_traces(
            hovertemplate="<b>%{x}</b> — %{fullData.name}<br>Count: %{y}<br><br>CVEs:<br>%{customdata[0]}<extra></extra>",
        )
        fig_b.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8", size=11),
            margin=dict(l=0, r=0, t=10, b=0),
            legend=dict(bgcolor="rgba(0,0,0,0)"),
            xaxis=dict(gridcolor="#1e3a5f"),
            yaxis=dict(gridcolor="#1e3a5f"),
        )
        st.plotly_chart(fig_b, use_container_width=True)

    # ── Critical & Ransomware tables ───────────────────────────────────────
    t1, t2 = st.columns(2)

    with t1:
        chart_header("🔴 Critical Severity CVEs",
            "This table lists the CVEs in the current filtered dataset that are rated as 'Critical' severity, along with key details such as vendor, product, vulnerability name, whether they are known to be used in ransomware attacks, and if they are subject to a CISA directive. Use this to quickly identify which critical vulnerabilities may require immediate attention.",
            "info_critical_cves")
        crit = filt[filt["Severity"] == "Critical"][
            ["CVE ID", "Vendor / Project", "Product",
                "Vulnerability Name", "Ransomware Use", "CISA Directive"]
        ].reset_index(drop=True)
        if crit.empty:
            st.info("No Critical CVEs in current filter selection.")
        else:
            st.dataframe(crit, use_container_width=True, hide_index=True)

    with t2:
        chart_header("☣️ Ransomware-Linked CVEs",
            "This table lists the CVEs in the current filtered dataset that are known to be used in ransomware attacks, along with key details such as vendor, product, vulnerability name, and if they are subject to a CISA directive. Use this to quickly identify which ransomware-linked vulnerabilities may require immediate attention.",
            "info_ransomware_cves")
        ransom = filt[filt["Ransomware Use"] == "Known"][
            ["CVE ID", "Vendor / Project", "Product",
                "Severity", "Date Added", "Due Date"]
        ].reset_index(drop=True)
        if ransom.empty:
            st.info("No ransomware-linked CVEs in current filter selection.")
        else:
            st.dataframe(ransom, use_container_width=True, hide_index=True)

    # ── Full filtered table ────────────────────────────────────────────────
    chart_header("📋 Full KEV Entry List (Filtered)",
            "This full table lists all CVEs that meet the current filter criteria, along with key details such as severity, vendor, product, vulnerability name, ransomware use, CISA directive status, CVSS base score, impact, and exploitability. Use this comprehensive view to analyze the specific vulnerabilities that are relevant to your organization based on the filters you've applied.",
            "info_full_table")

    display_cols = [
        "CVE ID", "Vendor / Project", "Product", "Vulnerability Name",
        "Severity", "Date Added", "Due Date", "Ransomware Use",
        "CISA Directive", "Base", "Impact", "Exploitability",
    ]
    st.dataframe(
        filt[display_cols]
        .sort_values("Date Added", ascending=False)
        .reset_index(drop=True),
        use_container_width=True,
        hide_index=True,
    )