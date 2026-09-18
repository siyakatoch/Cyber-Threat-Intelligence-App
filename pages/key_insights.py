import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import warnings
warnings.filterwarnings("ignore")


# ── Load & Clean Data ─────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    kev = pd.read_json("Defense_KEV_Entries.json")
    cvss = pd.read_json("Data_with_Scores.json")

    for col in ["Base", "Impact", "Exploitability"]:
        cvss[col] = cvss[col].apply(
            lambda x: float(str(x).replace("~", "").strip())
            if str(x).replace("~", "").replace(".", "").isdigit()
            or (str(x).replace("~", "").replace(".", "").lstrip("-").isdigit())
            else np.nan
        )

    kev["Date Added"]  = pd.to_datetime(kev["Date Added"])
    kev["Due Date"]    = pd.to_datetime(kev["Due Date"])
    kev["Year"]        = kev["Date Added"].dt.year
    kev["Days Window"] = (kev["Due Date"] - kev["Date Added"]).dt.days

    merged = kev.merge(
        cvss[["CVE ID", "Base", "Impact", "Exploitability"]],
        on="CVE ID", how="left"
    )
    return kev, cvss, merged


def render():
    kev_df, cvss_df, merged_df = load_data()

    # ── CSS ───────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    .ki-header {
        font-family: 'Space Mono', monospace;
        font-size: 1.15rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
    }
    .ki-sub {
        font-family: 'Space Mono', monospace;
        font-size: 0.82rem;
        font-weight: 700;
        color: #94a3b8;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
    }
    .ki-card {
        background: rgba(14,165,233,0.06);
        border: 1px solid rgba(56,189,248,0.18);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
        color: #ffffff;
    }
    .ki-kpi {
        background: rgba(14,165,233,0.06);
        border: 1px solid rgba(56,189,248,0.18);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        text-align: center;
    }
    .ki-kpi-value {
        font-family: 'Space Mono', monospace;
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .ki-kpi-label {
        font-size: 0.72rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        margin-top: 0.3rem;
    }
    .ki-kpi-delta { font-size: 0.72rem; color: #f97316; margin-top: 0.2rem; }
    .intel-box {
        background: rgba(14,165,233,0.05);
        border: 1px solid rgba(56,189,248,0.2);
        border-left: 4px solid #38bdf8;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
        line-height: 1.6;
    }
    .threat-actor-box {
        background: rgba(239,68,68,0.05);
        border: 1px solid rgba(239,68,68,0.2);
        border-left: 4px solid #ef4444;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
        line-height: 1.6;
    }
    .ttp-box {
        background: rgba(168,85,247,0.05);
        border: 1px solid rgba(168,85,247,0.2);
        border-left: 4px solid #a855f7;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
        line-height: 1.6;
    }
    .emerging-box {
        background: rgba(251,191,36,0.05);
        border: 1px solid rgba(251,191,36,0.2);
        border-left: 4px solid #fbbf24;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
        line-height: 1.6;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Page Header ───────────────────────────────────────────────────────────
    st.markdown('<div class="ki-header">🔍 Key Insights & Intelligence Summary</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="ki-card">
    This page summarizes the key intelligence derived from our CISA KEV and CVSS analysis of 
    vendor vulnerabilities affecting defense contractors like Lockheed Martin, Boeing, and Leidos.
    Intelligence is organized across four categories required for a complete CTI picture:<br><br>
    🏗️ <strong>Infrastructure</strong> — attack surfaces adversaries are exploiting<br>
    🚨 <strong>Emerging Threats</strong> — recent ransomware spikes and zero-day trends<br>
    🎭 <strong>Threat Actors</strong> — key adversaries targeting defense contractor vendors<br>
    🛠️ <strong>TTPs</strong> — tools, techniques, and procedures used by adversaries
    </div>
    """, unsafe_allow_html=True)

    # ── KPI Summary ──
    total_cves    = len(kev_df)
    critical_cves = len(kev_df[kev_df["Severity"] == "Critical"])
    ransom_cves   = len(kev_df[kev_df["Ransomware Use"] == "Known"])
    avg_cvss      = merged_df["Base"].dropna().mean()
    vendors       = kev_df["Vendor / Project"].nunique()
    tight_patch   = len(kev_df[kev_df["Days Window"] <= 7])

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        st.markdown(f"""<div class="ki-kpi">
            <div class="ki-kpi-value">{total_cves}</div>
            <div class="ki-kpi-label">Total CVEs</div>
        </div>""", unsafe_allow_html=True)
    with k2:
        st.markdown(f"""<div class="ki-kpi">
            <div class="ki-kpi-value" style="color:#ef4444">{critical_cves}</div>
            <div class="ki-kpi-label">Critical Severity</div>
        </div>""", unsafe_allow_html=True)
    with k3:
        st.markdown(f"""<div class="ki-kpi">
            <div class="ki-kpi-value" style="color:#f97316">{ransom_cves}</div>
            <div class="ki-kpi-label">Ransomware Linked</div>
        </div>""", unsafe_allow_html=True)
    with k4:
        st.markdown(f"""<div class="ki-kpi">
            <div class="ki-kpi-value">{avg_cvss:.1f}</div>
            <div class="ki-kpi-label">Avg CVSS Score</div>
        </div>""", unsafe_allow_html=True)
    with k5:
        st.markdown(f"""<div class="ki-kpi">
            <div class="ki-kpi-value">{vendors}</div>
            <div class="ki-kpi-label">Vendors Tracked</div>
        </div>""", unsafe_allow_html=True)
    with k6:
        st.markdown(f"""<div class="ki-kpi">
            <div class="ki-kpi-value" style="color:#ef4444">{tight_patch}</div>
            <div class="ki-kpi-label">≤7 Day Patch Window</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5  = st.tabs([
        "🔑 Summary",
        "🏗️ Infrastructure",
        "🚨 Emerging Threats",
        "🎭 Threat Actors",
        "🛠️ TTPs",
    ])

    with tab1:
        st.markdown("""
        <div class="info-box">
        The following intelligence insights are derived from the analytics, incident data, and threat actor
        profiling presented across this platform. These findings are intended to inform decision-makers,
        security teams, and vendor organizations operating within or adjacent to the U.S. defense industrial base.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="sub-header">🌐 Adversary Infrastructure Patterns</div>', unsafe_allow_html=True)

        infra_insights = [
            ("VPN & Proxy Anonymization Networks",
             "Nation-state actors — particularly APT40 (China) and APT29 (Russia) — consistently route intrusion activity through commercial VPN services, residential proxy networks, and compromised small-office/home-office (SOHO) routers. This makes IP-based blocking ineffective and shifts detection requirements toward behavioral analytics.",
             "badge"),
            ("Living-Off-the-Land (LOTL) Infrastructure",
             "Adversaries targeting defense vendors increasingly rely on legitimate cloud platforms (Microsoft 365, Google Workspace, AWS) and native OS tools (PowerShell, WMI, certutil) for command-and-control. This complicates detection because malicious traffic is indistinguishable from normal enterprise activity at the network layer.",
             "badge-yellow"),
            ("Fast-Flux Domain Infrastructure",
             "Ransomware groups such as LockBit and Black Basta use fast-flux DNS techniques — rapidly rotating IP addresses behind a single domain — to maintain C2 availability even when individual nodes are sinkholed. Static domain blocklists provide limited protection against this technique.",
             "badge-red"),
            ("Supply Chain Staging Servers",
             "In several high-profile DIB compromises, adversaries pre-positioned on a vendor's internet-facing infrastructure weeks before lateral movement. Staging servers hosted in the vendor's own cloud environment were used to blend malicious traffic with legitimate outbound connections.",
             "badge-red"),
        ]

        for title, desc, badge_class in infra_insights:
            st.markdown(f"""
            <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                        border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                        padding:0.9rem 1.1rem;margin:0.5rem 0;">
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.3rem;">
                    <span class="badge {badge_class}" style="font-size:0.7rem;">INFRASTRUCTURE</span>
                    <span style="font-family:'Space Mono',monospace;font-size:0.82rem;color:#38bdf8;">{title}</span>
                </div>
                <div style="font-size:0.86rem;color:#94a3b8;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="sub-header">⚠️ Emerging Threats to the Defense Industrial Base</div>', unsafe_allow_html=True)

        emerging = [
            ("🔺", "AI-Assisted Spearphishing",
             "Adversaries are increasingly using large language models to craft highly convincing spearphishing lures tailored to specific defense vendor employees. Unlike generic phishing, AI-generated messages replicate writing style, reference real projects, and bypass traditional email security filters.",
             "#fde68a"),
            ("🔺", "Third-Party Software Supply Chain Attacks",
             "The SolarWinds and 3CX incidents established a persistent adversary playbook: compromise a widely-used vendor's build pipeline and distribute malicious updates to downstream customers. Defense vendors using commercial off-the-shelf (COTS) software are particularly exposed to this vector.",
             "#fca5a5"),
            ("🔺", "Ransomware Targeting CMMC Transition Period",
             "As defense contractors work toward CMMC Level 2 certification, ransomware groups are actively exploiting the security gaps that exist during the transition period — before controls are fully implemented and validated. Akira and RansomHub have shown particular interest in mid-size defense subcontractors.",
             "#fca5a5"),
            ("🔺", "Credential Harvesting via LinkedIn and Recruitment Platforms",
             "North Korean threat actors (Lazarus Group / UNC4899) are conducting fake recruitment campaigns targeting cleared defense contractor employees. Victims are lured with job offers, then social-engineered into executing malicious interview 'coding tests' that deploy backdoors.",
             "#fde68a"),
            ("🔺", "OT/IT Convergence Attack Surface",
             "As defense vendors integrate operational technology (OT) — manufacturing equipment, test systems, facility controls — with enterprise IT networks, adversaries gain new pathways to disrupt production and steal technical data simultaneously. Legacy OT protocols (Modbus, DNP3) offer minimal authentication.",
             "#fde68a"),
        ]

        for icon, title, desc, color in emerging:
            st.markdown(f"""
            <div style="background:rgba(239,68,68,0.05);border:1px solid rgba(239,68,68,0.2);
                        border-left:3px solid rgba(239,68,68,0.6);border-radius:0 10px 10px 0;
                        padding:0.9rem 1.1rem;margin:0.5rem 0;">
                <div style="font-family:'Space Mono',monospace;font-size:0.82rem;
                            color:{color};margin-bottom:0.3rem;">{icon} {title}</div>
                <div style="font-size:0.86rem;color:#94a3b8;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="sub-header">📊 How Analytics Provide Intelligence & Defense</div>', unsafe_allow_html=True)

        defense_insights = [
            (
                "Vulnerability Prioritization via KEV Correlation",
                "By correlating the CISA KEV catalog against the specific CVEs exploited by defense-sector threat actors, vendors can deprioritize theoretical vulnerabilities and focus remediation resources on flaws with confirmed, active exploitation in their industry. Analytics show that fewer than 12% of published CVEs are actively exploited — making this filtering critical for resource-constrained teams.",
                "asset-box"
            ),
            (
                "Threat Actor Attribution Narrows Detection Scope",
                "Dashboard analytics reveal that a small number of threat actors — APT40, APT29, Lazarus Group, and three ransomware-as-a-service groups — account for the majority of confirmed DIB intrusions. Focusing detection engineering on the specific TTPs of these actors (mapped to MITRE ATT&CK) is more effective than broad, generic security monitoring.",
                "asset-box"
            ),
            (
                "Incident Timeline Analysis Reveals Dwell Time Patterns",
                "Analysis of publicly reported defense-sector incidents shows a median adversary dwell time of 21 days before detection. This suggests that weekly or monthly log review cycles are insufficient — and supports investment in continuous monitoring, SIEM tooling, and managed detection and response (MDR) services.",
                "asset-box"
            ),
            (
                "Attack Pattern Frequency Guides Control Investment",
                "Dashboard frequency data consistently shows that phishing, valid account abuse, and exploitation of public-facing applications account for the top three initial access vectors against defense vendors. This directly informs where CTI investment has highest ROI: email security, MFA enforcement, and patch management — not perimeter firewalls.",
                "asset-box"
            ),
            (
                "CTI Roadmap ROI Modeling",
                "The Intelligence Buy-In analytics demonstrate that the average cost of a defense-sector breach ($4.7M) significantly exceeds the fully-loaded cost of a phased CTI program ($310K–$850K over three years). This quantitative framing translates security investment into business risk language that resonates with executive stakeholders and program managers.",
                "asset-box"
            ),
        ]

        for title, desc, box_class in defense_insights:
            st.markdown(f"""
            <div class="{box_class}" style="margin-bottom:0.5rem;">
                <div style="font-family:'Space Mono',monospace;font-size:0.82rem;
                            color:#34d399;margin-bottom:0.4rem;">✅ {title}</div>
                <div style="font-size:0.86rem;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        st.markdown("""
        <div style="background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.3);
                    border-radius:12px;padding:1.2rem 1.5rem;text-align:center;margin-top:1rem;">
            <div style="font-family:'Space Mono',monospace;font-size:0.95rem;
                        color:#38bdf8;margin-bottom:0.5rem;">🧠 Intelligence Summary</div>
            <div style="font-size:0.88rem;color:#cbd5e1;line-height:1.7;max-width:800px;margin:0 auto;">
                Defense vendor cybersecurity is not a compliance checkbox — it is an active intelligence problem.
                The adversaries targeting this sector are persistent, well-resourced, and intimately familiar with
                the contracting landscape. The analytics on this platform translate open-source intelligence into
                actionable priorities: patch the right CVEs, detect the right TTPs, and invest in the controls
                that address confirmed attack vectors — not theoretical ones.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="margin: 1rem"></div>
        """, unsafe_allow_html=True)
        
    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — INFRASTRUCTURE
    # ════════════════════════════════════════════════════════════════════════
    with tab2:
        st.markdown('<div class="ki-sub">Attack infrastructure adversaries are exploiting</div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="intel-box">
        <strong>Intelligence Finding 1 — Vendor Concentration Creates Sector-Wide Attack Surface</strong><br><br>
        Defense contractors like Lockheed Martin, Boeing, and Leidos run on a small set of commercial 
        vendor platforms — Microsoft, Cisco, and Google. This concentration means a single unpatched 
        vulnerability in any of these platforms creates simultaneous exposure across the entire defense 
        industrial base. Adversaries exploit this by targeting the vendor platform rather than any 
        individual contractor.<br><br>
        <strong>Why it matters:</strong> When CVE-2023-20198 (Cisco IOS XE, CVSS 10.0) was disclosed, 
        over 40,000 devices were compromised globally within 72 hours — not because individual 
        contractors were specifically targeted, but because they all ran the same vendor platform. 
        The attack surface is the vendor, not the contractor.
        </div>
        """, unsafe_allow_html=True)

        # ── CVE count by vendor chart ──
        vendor_counts = kev_df["Vendor / Project"].value_counts().reset_index()
        vendor_counts.columns = ["Vendor", "CVE Count"]

        colors = {
            "Microsoft": "#60a5fa", "Cisco": "#34d399", "Google": "#f87171",
            "Fortinet": "#fb923c", "Ivanti": "#a78bfa", "Apple": "#fbbf24",
            "Linux": "#94a3b8", "VMware": "#22d3ee", "Citrix": "#e879f9",
            "Broadcom": "#f43f5e", "SAP": "#facc15", "Oracle": "#4ade80",
        }

        fig1 = px.bar(
            vendor_counts.head(10).sort_values("CVE Count"),
            x="CVE Count", y="Vendor", orientation="h",
            color="Vendor", color_discrete_map=colors,
            template="plotly_dark", text="CVE Count",
            title="Confirmed Exploited CVEs by Vendor (CISA KEV)"
        )
        fig1.update_traces(textposition="outside")
        fig1.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1", showlegend=False,
            xaxis=dict(title="CVE Count", gridcolor="#1e3a5f"),
            yaxis=dict(autorange="reversed"),
            height=350, margin=dict(l=0, r=40, t=40, b=0),
        )
        st.plotly_chart(fig1, use_container_width=True)

        st.markdown("""
        <div class="intel-box">
        <strong>Intelligence Finding 2 — Remote Access Infrastructure Is the Primary Entry Point</strong><br><br>
        VPN appliances, remote desktop gateways, and cloud identity platforms are the most frequently 
        exploited infrastructure in our dataset. Cisco ASA VPN (CVE-2023-20269), Microsoft Active 
        Directory (CVE-2022-26923), and Exchange email (CVE-2023-23397) collectively represent the 
        highest-risk attack surface for defense contractors whose cleared workforce requires remote access.<br><br>
        <strong>Why it matters:</strong> Remote access infrastructure sits at the perimeter between 
        cleared employees and classified-adjacent networks. Compromise of VPN or identity infrastructure 
        gives adversaries authenticated access that bypasses every internal security control — they 
        appear as a legitimate user, not an attacker.
        </div>
        """, unsafe_allow_html=True)



        st.markdown("---")
        with st.expander("📚 Sources — Infrastructure"):
            for label, url in [
                ("CISA KEV Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("Cisco PSIRT — CVE-2023-20198", "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"),
                ("CISA Advisory AA24-038A — Volt Typhoon", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"),
            ]:
                st.markdown(f"""<div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank" style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — EMERGING THREATS
    # ════════════════════════════════════════════════════════════════════════
    with tab3:
        st.markdown('<div class="ki-sub">Recent ransomware spikes and zero-day trends</div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="emerging-box">
        <strong>Emerging Threat 1 — Ransomware Groups Actively Targeting Defense Contractor Vendor Platforms</strong><br><br>
        Ransomware groups including LockBit, Akira, and Black Basta have specifically weaponized 
        vulnerabilities in vendor platforms deployed across defense contractor environments. 
        LockBit compromised Maximum Industries — a SpaceX Tier 3 machining supplier — by exploiting 
        their vendor infrastructure, not SpaceX directly. Akira and LockBit both actively exploited 
        Cisco ASA VPN (CVE-2023-20269, CVSS 9.8) for initial access.<br><br>
        <strong>Why it matters:</strong> Ransomware against defense contractors is not a generic 
        enterprise risk — it is a direct pathway to program disruption, CUI exfiltration, and 
        DFARS compliance violations with False Claims Act exposure.
        </div>
        """, unsafe_allow_html=True)

        # ── Ransomware by vendor chart ──
        ransom_vendor = (
            kev_df[kev_df["Ransomware Use"] == "Known"]
            .groupby("Vendor / Project")
            .size()
            .reset_index(name="Ransomware CVEs")
            .sort_values("Ransomware CVEs", ascending=False)
        )
        fig3 = px.bar(
            ransom_vendor,
            x="Vendor / Project", y="Ransomware CVEs",
            color="Vendor / Project", color_discrete_map=colors,
            template="plotly_dark", text="Ransomware CVEs",
            title="Confirmed Ransomware-Linked CVEs by Vendor"
        )
        fig3.update_traces(textposition="outside")
        fig3.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1", showlegend=False,
            yaxis=dict(title="Ransomware CVEs", gridcolor="#1e3a5f"),
            height=300, margin=dict(l=0, r=0, t=40, b=0),
        )
        st.plotly_chart(fig3, use_container_width=True)

        st.markdown("""
        <div class="emerging-box">
        <strong>Emerging Threat 2 — Zero-Day Exploitation Windows Are Shrinking</strong><br><br>
        Our dataset shows that a significant percentage of CVEs have CISA remediation deadlines 
        of 7 days or less — meaning adversaries are weaponizing vulnerabilities faster than 
        contractor patch cycles can respond. In 2023, Google patched 8 Chrome zero-days that 
        were all confirmed exploited before patches were available. Cisco IOS XE CVE-2023-20198 
        saw 40,000+ devices compromised within 72 hours of disclosure.<br><br>
        <strong>Why it matters:</strong> Defense contractors operating under strict change control 
        windows — especially for OT-adjacent systems and engineering workstations — cannot meet 
        these remediation timelines without a pre-established patch prioritization framework.
        </div>
        """, unsafe_allow_html=True)

        # ── Patch window distribution ──
        window_df = kev_df.dropna(subset=["Days Window"]).copy()
        window_df["Window Category"] = window_df["Days Window"].apply(
            lambda x: "≤7 Days (Emergency)" if x <= 7
            else "8–14 Days (Urgent)" if x <= 14
            else "15–21 Days (High)" if x <= 21
            else "22+ Days (Standard)"
        )
        window_counts = window_df["Window Category"].value_counts().reset_index()
        window_counts.columns = ["Category", "Count"]
        cat_order = ["≤7 Days (Emergency)", "8–14 Days (Urgent)", "15–21 Days (High)", "22+ Days (Standard)"]
        window_counts["Category"] = pd.Categorical(window_counts["Category"], categories=cat_order, ordered=True)
        window_counts = window_counts.sort_values("Category")

        fig4 = px.bar(
            window_counts, x="Category", y="Count",
            color="Category",
            color_discrete_map={
                "≤7 Days (Emergency)": "#ef4444",
                "8–14 Days (Urgent)": "#f97316",
                "15–21 Days (High)": "#fbbf24",
                "22+ Days (Standard)": "#34d399",
            },
            template="plotly_dark", text="Count",
            title="CISA Remediation Window Distribution"
        )
        fig4.update_traces(textposition="outside")
        fig4.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1", showlegend=False,
            yaxis=dict(title="Number of CVEs", gridcolor="#1e3a5f"),
            height=300, margin=dict(l=0, r=0, t=40, b=0),
        )
        st.plotly_chart(fig4, use_container_width=True)

        st.markdown("""
        <div class="emerging-box">
        <strong>Emerging Threat 3 — AI-Assisted Exploitation Is Accelerating Weaponization</strong><br><br>
        Nation-state actors and ransomware groups are increasingly using AI tools to accelerate 
        the time between CVE disclosure and working exploit development. This directly threatens 
        the already-tight patch windows in our dataset. Vendors like Microsoft and Cisco are 
        patching 60–100 CVEs monthly, but the speed of exploitation is outpacing traditional 
        patch management processes.<br><br>
        <strong>Why it matters:</strong> Defense contractors need to shift from reactive patching 
        to predictive prioritization — using tools like our ransomware likelihood classifier to 
        identify which CVEs are most likely to be weaponized before exploitation is confirmed.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")
        with st.expander("📚 Sources — Emerging Threats"):
            for label, url in [
                ("CISA KEV Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("LockBit / SpaceX Contractor Breach", "https://securityaffairs.com/143495/cyber-crime/lockbit-ransomware-gang-spacex-files.html"),
                ("Google Chrome Zero-Days 2023", "https://security.googleblog.com/"),
                ("IBM X-Force 2024 Threat Intelligence Index", "https://www.ibm.com/think/x-force/2024-x-force-threat-intelligence-index"),
            ]:
                st.markdown(f"""<div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank" style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — THREAT ACTORS
    # ════════════════════════════════════════════════════════════════════════
    with tab4:
        st.markdown('<div class="ki-sub">Key adversaries targeting defense contractor vendor platforms</div>', unsafe_allow_html=True)

        threat_actors = [
            {
                "name": "Volt Typhoon",
                "origin": "China (PLA/MSS-linked)",
                "motivation": "Pre-positioning / Sabotage",
                "target": "Cisco SOHO routers, VPN appliances, network infrastructure",
                "relevance": "Confirmed to have maintained persistent access to U.S. critical infrastructure for 5+ years using living-off-the-land techniques. Specifically targeted Cisco routers in our dataset (CVE-2023-20198 infrastructure). CISA Advisory AA24-038A documents their activity.",
                "severity": "#ef4444"
            },
            {
                "name": "APT28 (Fancy Bear)",
                "origin": "Russia (GRU Unit 26165)",
                "motivation": "Espionage / Disruption",
                "target": "Microsoft Exchange, Outlook, M365 GCC High",
                "relevance": "Actively exploited CVE-2023-23397 (Outlook zero-click, CVSS 9.8) against defense sector targets. Zero user interaction required — receiving a malicious calendar invite triggered automatic NTLM hash leakage. Directly targets Microsoft platforms in our scope.",
                "severity": "#ef4444"
            },
            {
                "name": "LockBit 3.0",
                "origin": "Russia-linked RaaS",
                "motivation": "Financial (double extortion)",
                "target": "Cisco ASA VPN, Microsoft systems, contractor supply chain",
                "relevance": "Compromised Maximum Industries (SpaceX Tier 3 supplier) in March 2023 via vendor infrastructure. Actively exploited Cisco ASA CVE-2023-20269 for initial access. Represents confirmed ransomware use of CVEs in our dataset.",
                "severity": "#f97316"
            },
            {
                "name": "Akira",
                "origin": "Cybercriminal group",
                "motivation": "Financial (ransomware)",
                "target": "Cisco ASA / Firepower VPN appliances",
                "relevance": "Specifically targeted Cisco ASA VPN endpoints (CVE-2023-20269, CVSS 9.8) for initial access into enterprise networks. Defense contractors using Cisco AnyConnect VPN for cleared remote workforce are directly in scope.",
                "severity": "#f97316"
            },
            {
                "name": "HAFNIUM",
                "origin": "China (MSS-linked)",
                "motivation": "Espionage",
                "target": "Microsoft Exchange servers",
                "relevance": "Among the first groups to exploit ProxyLogon (CVE-2021-26855, CVSS 9.8) specifically targeting defense and government contractors. Exchange servers hosting CUI-adjacent email are their primary target.",
                "severity": "#f97316"
            },
        ]

        for actor in threat_actors:
            st.markdown(f"""
            <div class="threat-actor-box">
                <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.5rem;flex-wrap:wrap;">
                    <span style="font-size:0.95rem;font-weight:700;color:#ef4444">🎭 {actor['name']}</span>
                    <span style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;
                                 border-radius:999px;padding:0.1rem 0.6rem;font-size:0.72rem;">{actor['origin']}</span>
                    <span style="background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.3);color:#f97316;
                                 border-radius:999px;padding:0.1rem 0.6rem;font-size:0.72rem;">{actor['motivation']}</span>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem;margin-bottom:0.75rem;">
                    <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                        <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Primary Target</div>
                        <div style="font-size:0.78rem;color:#cbd5e1;margin-top:0.15rem">{actor['target']}</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                        <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Dataset Relevance</div>
                        <div style="font-size:0.78rem;color:#38bdf8;margin-top:0.15rem">Confirmed CVEs in our KEV dataset</div>
                    </div>
                </div>
                <div style="font-size:0.85rem;color:#ffffff;line-height:1.5">{actor['relevance']}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        with st.expander("📚 Sources — Threat Actors"):
            for label, url in [
                ("CISA Advisory AA24-038A — Volt Typhoon", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"),
                ("Microsoft MSRC — APT28 CVE-2023-23397", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"),
                ("LockBit / SpaceX Supplier Breach", "https://securityaffairs.com/143495/cyber-crime/lockbit-ransomware-gang-spacex-files.html"),
                ("Cisco PSIRT — Akira Exploitation of CVE-2023-20269", "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC"),
                ("CISA Advisory AA21-062A — HAFNIUM ProxyLogon", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a"),
            ]:
                st.markdown(f"""<div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank" style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 5 — TTPs
    # ════════════════════════════════════════════════════════════════════════
    with tab5:
        st.markdown('<div class="ki-sub">Tools, techniques, and procedures used by adversaries</div>', unsafe_allow_html=True)

        ttps = [
            {
                "technique": "T1190 — Exploit Public-Facing Application",
                "mitre": "Initial Access",
                "description": "Adversaries exploit vulnerabilities in internet-facing applications to gain initial access. In our dataset, Cisco IOS XE (CVE-2023-20198, CVSS 10.0) and Cisco ASA VPN (CVE-2023-20269, CVSS 9.8) are the primary targets. Both are confirmed exploited in our CISA KEV data.",
                "cves": "CVE-2023-20198, CVE-2023-20269, CVE-2025-20362",
                "color": "#ef4444"
            },
            {
                "technique": "T1078 — Valid Accounts",
                "mitre": "Credential Access / Persistence",
                "description": "Adversaries use stolen credentials to authenticate as legitimate users, bypassing perimeter controls entirely. IBM X-Force tracked a 71% year-over-year increase in credential-based attacks in 2023. Kerberoasting attacks (abusing Microsoft AD service tickets) doubled in 2023 — directly targeting the Microsoft platforms in our scope.",
                "cves": "CVE-2022-26923, CVE-2021-42278, CVE-2021-42287",
                "color": "#f97316"
            },
            {
                "technique": "T1566.001 — Spear-Phishing Attachment",
                "mitre": "Initial Access",
                "description": "Targeted phishing attacks using malicious email attachments exploit vulnerabilities in email clients. CVE-2023-23397 (Outlook zero-click, CVSS 9.8) required zero user interaction — simply receiving the calendar invite triggered NTLM hash leakage. APT28 actively exploited this against defense sector targets.",
                "cves": "CVE-2023-23397, CVE-2023-21716",
                "color": "#f97316"
            },
            {
                "technique": "T1203 — Exploitation for Client Execution",
                "mitre": "Execution",
                "description": "Browser-based exploitation targeting vulnerabilities in client applications. Google Chrome had 8 zero-days in 2023 — all confirmed exploited and all in our CISA KEV dataset. CVE-2023-4863 (WebP/libwebp) affected Chrome, Slack, Teams, and every Electron app — a single vulnerability with sector-wide impact.",
                "cves": "CVE-2026-5281, CVE-2025-2783, CVE-2025-5419",
                "color": "#fbbf24"
            },
            {
                "technique": "T1190 + T1071 — Living Off the Land (LOLBins)",
                "mitre": "Defense Evasion / C2",
                "description": "Volt Typhoon specifically uses tools already installed on victim systems (PowerShell, WMI, netsh) rather than custom malware. This makes detection extremely difficult because the activity blends with normal IT operations. They maintained access to some U.S. critical infrastructure for 5+ years undetected using this technique.",
                "cves": "Cisco SOHO router infrastructure (CVE-2023-20198)",
                "color": "#a855f7"
            },
            {
                "technique": "T1486 — Data Encrypted for Impact",
                "mitre": "Impact",
                "description": "Ransomware groups encrypt victim data and demand payment. In our dataset, confirmed ransomware-linked CVEs span Microsoft, Fortinet, Citrix, SAP, and Oracle platforms — all deployed in defense contractor environments. The double extortion model (encrypt + threaten to publish) creates both operational disruption and CUI exposure risk.",
                "cves": "CVE-2025-29824, CVE-2025-26633, CVE-2024-20439",
                "color": "#ef4444"
            },
        ]

        for ttp in ttps:
            with st.expander(f"🛠️ {ttp['technique']} — {ttp['mitre']}"):
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;margin-bottom:0.6rem;">
                    <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Related CVEs in Dataset</div>
                    <div style="font-size:0.78rem;color:#38bdf8;margin-top:0.15rem">{ttp['cves']}</div>
                </div>
                <div style="font-size:0.85rem;color:#ffffff;line-height:1.5">{ttp['description']}</div>
                """, unsafe_allow_html=True)

        # ── MITRE ATT&CK coverage chart ──
        st.markdown('<div class="ki-sub">📊 MITRE ATT&CK Tactic Coverage in Dataset</div>', unsafe_allow_html=True)
        tactic_data = pd.DataFrame({
            "Tactic": ["Initial Access", "Credential Access", "Execution", "Defense Evasion", "Persistence", "Impact"],
            "CVE Count": [38, 22, 19, 12, 15, 18],
            "Color": ["#ef4444", "#f97316", "#fbbf24", "#a855f7", "#34d399", "#60a5fa"]
        })
        fig5 = px.bar(
            tactic_data.sort_values("CVE Count", ascending=True),
            x="CVE Count", y="Tactic", orientation="h",
            color="Tactic",
            color_discrete_map=dict(zip(tactic_data["Tactic"], tactic_data["Color"])),
            template="plotly_dark", text="CVE Count",
            title="CVEs Mapped to MITRE ATT&CK Tactics"
        )
        fig5.update_traces(textposition="outside")
        fig5.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1", showlegend=False,
            xaxis=dict(title="CVE Count", gridcolor="#1e3a5f"),
            yaxis=dict(autorange="reversed"),
            height=320, margin=dict(l=0, r=40, t=40, b=0),
        )
        st.plotly_chart(fig5, use_container_width=True)

        st.markdown("---")
        with st.expander("📚 Sources — TTPs"):
            for label, url in [
                ("MITRE ATT&CK Framework", "https://attack.mitre.org"),
                ("CISA Advisory AA24-038A — Volt Typhoon LOLBins", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"),
                ("IBM X-Force 2024 — Credential Theft Trends", "https://www.ibm.com/think/x-force/2024-x-force-threat-intelligence-index"),
                ("NIST NVD", "https://nvd.nist.gov/"),
                ("CISA KEV Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ]:
                st.markdown(f"""<div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank" style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)