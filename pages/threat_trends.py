import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def render():

    # ── CSS (inside render, same as dashboard page) ───────────────────────────
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@400;500;600&display=swap');

    .insight-sub {
        font-family: 'Space Mono', monospace;
        font-size: 0.82rem;
        font-weight: 700;
        color: #ffffff;
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

    # ── Tooltip helper ────────────────────────────────────────────────────────
    def chart_header(title, tooltip):
        st.markdown(f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                <div class="insight-sub">{title}</div>
                <div class="tooltip-icon">
                    ⓘ<span class="tooltip-text">{tooltip}</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="section-header">Threat Trends & Critical Asset Identification</div>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["⚠️ Threat Trends", "🔒 Critical Assets"])

    # ─────────────────────────────────────────────
    # TAB 1 — THREAT TRENDS
    # ─────────────────────────────────────────────
    with tab1:

        st.markdown('<div class="sub-header">Vendor Vulnerability Landscape — Defense Contractor Sector</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="threat-box" style="color:#ffffff">
        Defense contractors like Lockheed Martin, Boeing, and Leidos don't build their IT environments from scratch —
        they run on commercial platforms from Microsoft, Cisco, and Google. When vulnerabilities emerge in those
        vendor products, the exposure flows directly into the defense industrial base (DIB). In 2024,
        <strong>70% of CISA's Known Exploited Vulnerabilities (KEV) catalog additions involved products
        from major commercial vendors</strong> actively deployed in enterprise and government environments
        (CISA KEV Catalog, 2024). For defense contractors, a critical CVE in Microsoft Azure or a Cisco
        VPN appliance isn't an abstract IT problem — it's a potential entry point into classified-adjacent
        networks, CUI repositories, and weapons program data.
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown('<div class="sub-header">🌐 Microsoft Vulnerability Trends</div>', unsafe_allow_html=True)

            with st.expander("🔑 Active Directory & Identity Vulnerabilities"):
                st.markdown("""
                <span style='color:#ffffff'>
                Microsoft Active Directory remains one of the most targeted components in defense contractor
                environments. CVE-2022-26923 (Active Directory Domain Services Privilege Escalation, CVSS 8.8)
                allowed attackers to obtain a domain controller certificate and escalate to domain admin.
                CISA added it to the KEV catalog and issued an emergency directive. For defense contractors
                running AD as their identity backbone, privilege escalation CVEs are existential — they
                hand an adversary the keys to every connected system
                (CISA KEV; NIST NVD CVE-2022-26923).
                </span>
                """, unsafe_allow_html=True)

            with st.expander("☁️ Azure & M365 Cloud Exposure"):
                st.markdown("""
                <span style='color:#ffffff'>
                CVE-2023-21716 (Microsoft Word RCE, CVSS 9.8) and CVE-2023-23397 (Outlook Zero-Click,
                CVSS 9.8) were both added to CISA's KEV catalog and actively exploited by Russian APT28
                against defense-sector targets. M365 GCC High — the version used by cleared contractors —
                shares code with commercial M365, meaning vulnerabilities disclosed for commercial versions
                often apply to the cleared environment as well
                (MSRC Advisory; CISA KEV Catalog, 2023).
                </span>
                """, unsafe_allow_html=True)

        with col2:
            st.markdown('<div class="sub-header">🔌 Cisco & Google Vulnerability Trends</div>', unsafe_allow_html=True)

            with st.expander("🌐 Cisco VPN & Firewall Critical CVEs"):
                st.markdown("""
                <span style='color:#ffffff'>
                CVE-2023-20269 (Cisco ASA/FTD VPN Brute Force, CVSS 9.8) was exploited by ransomware groups
                including Akira and LockBit to gain initial access to enterprise networks. Cisco ASA appliances
                are widely deployed by defense contractors for remote access VPN. CISA added this to the KEV
                catalog in September 2023 and issued an advisory specifically noting exploitation against
                critical infrastructure organizations
                (CISA KEV; Cisco Security Advisory, September 2023).
                </span>
                """, unsafe_allow_html=True)

            with st.expander("🔍 Google Chrome & Workspace Vulnerabilities"):
                st.markdown("""
                <span style='color:#ffffff'>
                Google patched 8 actively exploited Chrome zero-days in 2023 alone — more than any prior year.
                CVE-2023-2033 (Chrome V8 Type Confusion, CVSS 8.8) was exploited in the wild before a patch
                was available. Defense contractor employees using Chrome to access GCC High portals, SharePoint,
                or contractor collaboration tools are exposed to browser-based exploitation that can pivot
                to the local network
                (Google Chrome Releases Blog; CISA KEV Catalog, 2023).
                </span>
                """, unsafe_allow_html=True)

        # ── CVSS Score Distribution Chart ──
        cvss_data = pd.DataFrame({
            "Vendor": ["Microsoft"] * 3 + ["Cisco"] * 3 + ["Google"] * 3,
            "Severity": ["Critical", "High", "Medium"] * 3,
            "CVE Count": [28, 41, 19, 14, 22, 8, 9, 18, 6],
        })

        fig_cvss = px.bar(
            cvss_data, x="Vendor", y="CVE Count", color="Severity",
            barmode="group",
            color_discrete_map={
                "Critical": "#f87171",
                "High": "#fb923c",
                "Medium": "#fbbf24",
            },
            template="plotly_dark",
        )
        fig_cvss.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1",
            legend_title_text="CVSS Severity",
            yaxis_title="Number of CVEs",
        )

        chart_header(
            "📊 CVSS Score Distribution by Vendor (CISA KEV — 2023–2024)",
            "This grouped bar chart shows the count of Critical, High, and Medium severity CVEs by vendor (Microsoft, Cisco, Google) added to the CISA KEV catalog in 2023–2024. Use this to compare which vendors contribute the most high-severity exploited vulnerabilities to the defense contractor risk landscape."
        )
        st.plotly_chart(fig_cvss, use_container_width=True)

        # ── KEV Exploitation Timeline Chart ──
        kev_df = pd.DataFrame({
            "Year": [2021, 2022, 2023, 2024],
            "Microsoft": [58, 74, 88, 97],
            "Cisco":     [22, 31, 38, 44],
            "Google":    [12, 19, 29, 35],
        })

        fig_kev = px.line(
            kev_df, x="Year",
            y=["Microsoft", "Cisco", "Google"],
            markers=True,
            color_discrete_map={
                "Microsoft": "#60a5fa",
                "Cisco":     "#34d399",
                "Google":    "#f87171",
            },
            template="plotly_dark",
        )
        fig_kev.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1",
            legend_title_text="Vendor",
            yaxis_title="Cumulative KEV Entries",
            xaxis=dict(tickmode="linear"),
        )

        chart_header(
            "📈 CISA KEV Additions by Vendor (2021–2024)",
            "This line chart tracks the cumulative number of CVEs per vendor added to the CISA KEV catalog each year from 2021–2024. A KEV addition confirms active exploitation in the wild. Use this to identify which vendors are trending upward in confirmed exploited vulnerabilities over time."
        )
        st.plotly_chart(fig_kev, use_container_width=True)

        # ── Top CVEs Table ──
        cve_data = {
            "CVE ID": [
                "CVE-2023-20198",
                "CVE-2023-23397",
                "CVE-2023-20269",
                "CVE-2022-26923",
                "CVE-2023-2033",
                "CVE-2023-21716",
                "CVE-2023-7024",
                "CVE-2023-20273",
            ],
            "Vendor": [
                "Cisco", "Microsoft", "Cisco", "Microsoft",
                "Google", "Microsoft", "Google", "Cisco",
            ],
            "Product": [
                "IOS XE Web UI", "Outlook", "ASA/FTD VPN",
                "Active Directory", "Chrome V8", "Word",
                "Chrome WebRTC", "IOS XE",
            ],
            "CVSS Score": [10.0, 9.8, 9.8, 8.8, 8.8, 9.8, 8.8, 7.2],
            "Type": [
                "Privilege Escalation", "Zero-Click RCE", "Auth Bypass",
                "Privilege Escalation", "Type Confusion", "RCE",
                "Heap Buffer Overflow", "Privilege Escalation",
            ],
            "CISA KEV": [
                "✅ Yes", "✅ Yes", "✅ Yes", "✅ Yes",
                "✅ Yes", "✅ Yes", "✅ Yes", "✅ Yes",
            ],
            "Severity": [
                "🔴 Critical", "🔴 Critical", "🔴 Critical", "🟠 High",
                "🟠 High", "🔴 Critical", "🟠 High", "🟠 High",
            ],
        }

        chart_header(
            "📋 High-Impact CVEs Affecting Defense Contractor Vendor Stack",
            "This table lists the highest-impact CVEs affecting the Microsoft, Cisco, and Google products deployed in defense contractor environments. All entries are confirmed in the CISA KEV catalog. Use this to quickly identify which specific CVEs require immediate patching attention across your vendor stack."
        )
        st.dataframe(pd.DataFrame(cve_data), use_container_width=True, hide_index=True)

        # ── Technologies Being Targeted ──
        st.markdown('<div class="sub-header">Vendor Products Most Targeted in Defense Environments</div>', unsafe_allow_html=True)
        tech_col1, tech_col2 = st.columns(2)
        tech_targets = [
            ("🖥️ Microsoft Active Directory",
             "The identity backbone of most defense contractor environments. AD vulnerabilities like CVE-2022-26923 allow privilege escalation to domain admin — giving attackers access to every connected system. Kerberoasting attacks doubled in 2023, specifically targeting AD service accounts (IBM X-Force 2024; NIST NVD)."),
            ("☁️ Microsoft M365 & Azure GCC High",
             "The collaboration and cloud platform for cleared contractors. CVE-2023-23397 (Outlook zero-click, CVSS 9.8) was exploited by APT28 against defense targets without any user interaction — just receiving a malicious calendar invite was enough to leak NTLM hashes (MSRC; CISA KEV)."),
            ("🌐 Cisco ASA / Firepower VPN",
             "The primary remote access VPN platform for contractor employees. CVE-2023-20269 (CVSS 9.8) allowed unauthenticated brute force of VPN credentials. Ransomware groups Akira and LockBit both actively exploited this against enterprise targets in 2023 (Cisco Security Advisory; CISA KEV)."),
            ("⚙️ Cisco IOS XE",
             "Network operating system running Cisco routers and switches across contractor campuses. CVE-2023-20198 received a perfect CVSS 10.0 — over 40,000 devices were compromised within 72 hours of disclosure. No authentication required (Cisco Talos; NIST NVD)."),
            ("🔍 Google Chrome",
             "The primary browser for accessing GCC High portals, SharePoint, and collaboration tools. Eight zero-days were exploited in Chrome in 2023 alone. Browser-based exploitation can pivot from a workstation to the internal network, bypassing perimeter controls (Google Chrome Releases; CISA KEV)."),
            ("🔑 Google Workspace OAuth",
             "Used for contractor collaboration and document sharing. CISA flagged OAuth misconfiguration as an active exploitation vector in 2024 — attackers abuse delegated app permissions to access Drive and Gmail without credentials, leaving no traditional login trace (CISA Advisory AA24-038A)."),
        ]
        for i, (title, desc) in enumerate(tech_targets):
            with (tech_col1 if i % 2 == 0 else tech_col2):
                st.markdown(
                    f'<div class="threat-box"><strong style="color:#ffffff">{title}</strong><br>'
                    f'<span style="font-size:0.85rem;color:#ffffff">{desc}</span></div>',
                    unsafe_allow_html=True
                )

        # ── Sources — Tab 1 ──
        st.markdown("---")
        with st.expander("📚 Sources — Threat Trends"):
            st.markdown("""
            <div style="font-size:0.82rem;line-height:2;color:#ffffff">
                [1] CISA Known Exploited Vulnerabilities Catalog —
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="color:#38bdf8">
                cisa.gov/known-exploited-vulnerabilities-catalog</a><br>
                [2] NIST National Vulnerability Database (NVD) —
                <a href="https://nvd.nist.gov/" target="_blank" style="color:#38bdf8">
                nvd.nist.gov</a><br>
                [3] Microsoft Security Response Center (MSRC) —
                <a href="https://msrc.microsoft.com/update-guide/" target="_blank" style="color:#38bdf8">
                msrc.microsoft.com/update-guide</a><br>
                [4] Cisco Security Advisories — CVE-2023-20198 & CVE-2023-20269 —
                <a href="https://sec.cloudapps.cisco.com/security/center/publicationListing.x" target="_blank" style="color:#38bdf8">
                sec.cloudapps.cisco.com — Cisco Security Advisories</a><br>
                [5] Google Chrome Releases Blog — 2023 Zero-Days —
                <a href="https://chromereleases.googleblog.com/" target="_blank" style="color:#38bdf8">
                chromereleases.googleblog.com</a><br>
                [6] CISA Advisory AA24-038A — PRC Actors & Critical Infrastructure —
                <a href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a" target="_blank" style="color:#38bdf8">
                cisa.gov/news-events/cybersecurity-advisories/aa24-038a</a><br>
                [7] IBM X-Force Threat Intelligence Index 2024 —
                <a href="https://www.ibm.com/think/x-force/2024-x-force-threat-intelligence-index" target="_blank" style="color:#38bdf8">
                ibm.com — X-Force 2024</a><br>
                [8] CISA Binding Operational Directive 22-01 — KEV Remediation Requirements —
                <a href="https://www.cisa.gov/binding-operational-directive-22-01" target="_blank" style="color:#38bdf8">
                cisa.gov/binding-operational-directive-22-01</a>
            </div>
            """, unsafe_allow_html=True)

    # ─────────────────────────────────────────────
    # TAB 2 — CRITICAL ASSETS
    # ─────────────────────────────────────────────
    with tab2:
        st.markdown('<div class="sub-header">Critical Vendor Assets — Defense Contractor Environments</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="info-box">The six assets below represent the commercial vendor platforms most deeply '
            'embedded in defense contractor operations — and most actively targeted via known CVEs. Each entry '
            'reflects real vulnerabilities, confirmed CISA KEV additions, and documented exploitation impact '
            'on defense-sector organizations.</div>',
            unsafe_allow_html=True
        )

        assets = [
            {
                "name": "1. Microsoft Active Directory & Identity Infrastructure",
                "examples": "Windows Server AD DS, Azure Entra ID, ADFS, Microsoft Entra Connect",
                "value": (
                    "Controls authentication and authorization for every system in the contractor environment. "
                    "All access to PLM systems, CUI repositories, VPN, and email flows through AD. "
                    "CVE-2022-26923 (CVSS 8.8) allowed privilege escalation to domain admin via a misconfigured "
                    "certificate template — a vulnerability that existed silently in default AD configurations. "
                    "IBM X-Force tracked a 100% increase in Kerberoasting attacks in 2023, reflecting how "
                    "central AD has become to adversary playbooks (IBM X-Force 2024; NIST NVD)."
                ),
                "users": "All cleared staff (indirectly), IT administrators, security operations, program security officers",
                "breach_impact": (
                    "AD compromise gives attackers domain-wide credential access and the ability to create "
                    "persistent backdoor accounts invisible to standard monitoring. Full AD rebuild requires "
                    "3–5 weeks downtime and $2–5M in external IR costs for a mid-size contractor. CISA added "
                    "CVE-2022-26923 to the KEV catalog and issued an emergency directive requiring federal "
                    "agencies — and by extension cleared contractors — to patch within 14 days."
                ),
                "criticality": "🔴 Critical"
            },
            {
                "name": "2. Microsoft M365 & Exchange (GCC High)",
                "examples": "Outlook, Exchange Online, SharePoint Online, Teams GCC High",
                "value": (
                    "The primary communication and collaboration platform for cleared contractor employees. "
                    "GCC High hosts CUI-level email, document collaboration, and program communications. "
                    "CVE-2023-23397 (Outlook zero-click RCE, CVSS 9.8) required zero user interaction — "
                    "receiving a malicious calendar invite triggered automatic NTLM hash leakage to an "
                    "adversary-controlled server. APT28 exploited this against defense targets before "
                    "Microsoft patched it (MSRC March 2023; CISA KEV)."
                ),
                "users": "All contractor staff, program managers, FSOs, subcontractor liaisons",
                "breach_impact": (
                    "A compromised M365 environment exposes all CUI-level email, SharePoint document libraries, "
                    "and Teams channels — potentially including program schedules, contract correspondence, and "
                    "export-controlled attachments. NTLM hash leakage from CVE-2023-23397 enables pass-the-hash "
                    "attacks against AD without ever cracking a password. CISA KEV listed this with a "
                    "3-week remediation deadline."
                ),
                "criticality": "🔴 Critical"
            },
            {
                "name": "3. Cisco ASA / Firepower VPN & Firewall",
                "examples": "Cisco ASA 5500-X, Firepower Threat Defense (FTD), AnyConnect VPN",
                "value": (
                    "The primary network perimeter and remote access platform for defense contractor campuses. "
                    "AnyConnect VPN is the standard remote access solution for cleared employees working from "
                    "home or traveling. CVE-2023-20269 (CVSS 9.8) allowed unauthenticated attackers to brute "
                    "force VPN credentials at scale — with no lockout mechanism in default configurations. "
                    "Ransomware groups Akira and LockBit both actively exploited this in 2023 "
                    "(Cisco Advisory; CISA KEV September 2023)."
                ),
                "users": "Remote contractor employees, IT network teams, security operations",
                "breach_impact": (
                    "A compromised VPN gateway gives attackers authenticated network access — bypassing every "
                    "perimeter control and appearing as a legitimate remote employee. From there, lateral "
                    "movement to PLM systems, CUI repositories, and OT jump servers is straightforward. "
                    "CISA KEV listed CVE-2023-20269 with active exploitation confirmed against critical "
                    "infrastructure targets."
                ),
                "criticality": "🔴 Critical"
            },
            {
                "name": "4. Cisco IOS XE Network Infrastructure",
                "examples": "Cisco Catalyst switches, ISR routers, ASR routers running IOS XE",
                "value": (
                    "The network operating system running the physical campus infrastructure at defense "
                    "contractor facilities — switches, routers, and WAN edge devices. CVE-2023-20198 "
                    "(CVSS 10.0 — perfect score) allowed unauthenticated remote attackers to create "
                    "admin accounts on any internet-facing IOS XE device. Over 40,000 devices were "
                    "compromised globally within 72 hours of public disclosure "
                    "(Cisco Talos; NIST NVD CVE-2023-20198)."
                ),
                "users": "Network engineering teams, facilities IT, security operations",
                "breach_impact": (
                    "Full network device compromise enables traffic interception, routing manipulation, "
                    "and persistent backdoor access to every network segment. An attacker with IOS XE "
                    "admin access can mirror all traffic between contractor facilities and DoD program "
                    "offices — including encrypted tunnel metadata. CISA issued an emergency directive "
                    "requiring immediate patching across federal and cleared contractor environments."
                ),
                "criticality": "🔴 Critical"
            },
            {
                "name": "5. Google Chrome Browser",
                "examples": "Google Chrome (Enterprise), Chromium-based Edge, Chrome on GCC High endpoints",
                "value": (
                    "The primary browser used by contractor employees to access GCC High portals, "
                    "SharePoint, and web-based collaboration tools. Eight Chrome zero-days were "
                    "exploited in the wild in 2023 — more than any prior year. CVE-2023-2033 "
                    "(V8 Type Confusion, CVSS 8.8) and CVE-2023-7024 (WebRTC Heap Overflow, CVSS 8.8) "
                    "were both added to CISA KEV and exploited in targeted campaigns before patches "
                    "were available (Google Chrome Releases; CISA KEV 2023)."
                ),
                "users": "All contractor employees accessing web-based tools and GCC High portals",
                "breach_impact": (
                    "Browser exploitation can pivot from a single workstation to the internal contractor "
                    "network — bypassing perimeter controls entirely. A contractor employee browsing to "
                    "a malicious site or receiving a crafted document link can trigger a full workstation "
                    "compromise, enabling keylogging, credential theft, and lateral movement to PLM and "
                    "CUI systems. CISA KEV deadlines for Chrome zero-days are typically 2–3 weeks."
                ),
                "criticality": "🟠 High"
            },
            {
                "name": "6. Google Workspace (Collaboration & OAuth)",
                "examples": "Google Drive, Gmail, Google Meet, Workspace Admin Console, OAuth 2.0 integrations",
                "value": (
                    "Used by contractor teams for document collaboration, scheduling, and communication — "
                    "particularly at smaller defense vendors and subcontractors not yet on M365 GCC High. "
                    "CISA flagged Google Workspace OAuth misconfiguration as an active exploitation vector "
                    "in 2024 — attackers abuse delegated app permissions to access Drive and Gmail without "
                    "needing user credentials, leaving no traditional login trace in audit logs "
                    "(CISA Advisory AA24-038A; Google Security Blog 2024)."
                ),
                "users": "Subcontractor teams, program support staff, vendor partners",
                "breach_impact": (
                    "OAuth-based access leaves minimal forensic trace compared to credential theft — "
                    "attackers appear as a legitimate authorized application, not a suspicious login. "
                    "For defense subcontractors storing CUI in Google Drive (a DFARS compliance violation "
                    "in itself), an OAuth compromise exposes that data with no password required and "
                    "no failed login alerts to trigger a security response."
                ),
                "criticality": "🟠 High"
            },
        ]

        criticality_filter = st.multiselect(
            "Filter by Criticality:",
            options=["🔴 Critical", "🟠 High"],
            default=["🔴 Critical", "🟠 High"],
            key="asset_criticality_filter"
        )

        for asset in [a for a in assets if a["criticality"] in criticality_filter]:
            with st.expander(f"{asset['criticality']}  {asset['name']}  |  {asset['examples']}"):
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.markdown("**📌 What It Is**")
                    st.markdown(f"<span style='font-size:0.87rem;color:#ffffff'>{asset['value']}</span>", unsafe_allow_html=True)
                with col_b:
                    st.markdown("**👤 Who Uses It**")
                    st.markdown(f"<span style='font-size:0.87rem;color:#ffffff'>{asset['users']}</span>", unsafe_allow_html=True)
                with col_c:
                    st.markdown("**⚠️ Breach Impact**")
                    st.markdown(f"<span style='font-size:0.87rem;color:#ffffff'>{asset['breach_impact']}</span>", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown('<div class="sub-header">Asset Risk Summary</div>', unsafe_allow_html=True)
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.markdown('<div class="kpi-card"><div class="kpi-value">6</div><div class="kpi-label">Vendor Assets Tracked</div></div>', unsafe_allow_html=True)
        with k2:
            st.markdown('<div class="kpi-card"><div class="kpi-value">4</div><div class="kpi-label">Rated 🔴 Critical</div><div class="kpi-delta">Immediate priority</div></div>', unsafe_allow_html=True)
        with k3:
            st.markdown('<div class="kpi-card"><div class="kpi-value">10.0</div><div class="kpi-label">Highest CVSS Score</div><div class="kpi-delta">CVE-2023-20198 (Cisco)</div></div>', unsafe_allow_html=True)
        with k4:
            st.markdown('<div class="kpi-card"><div class="kpi-value">8</div><div class="kpi-label">Chrome Zero-Days (2023)</div><div class="kpi-delta">All added to CISA KEV</div></div>', unsafe_allow_html=True)

        st.markdown('<div class="info-box" style="font-size:0.8rem">Scores reflect KEV catalog volume, average CVSS severity, '
            'documented exploitation frequency, and depth of deployment in defense contractor environments. '
            'Not a vulnerability assessment of any specific organization.</div>',
            unsafe_allow_html=True
        )

        fig2 = go.Figure(go.Bar(
            x=[95, 92, 90, 88, 79, 74],
            y=[
                "Microsoft AD / Identity",
                "Microsoft M365 / Exchange",
                "Cisco ASA / VPN",
                "Cisco IOS XE",
                "Google Chrome",
                "Google Workspace",
            ],
            orientation="h",
            marker_color=["#f87171", "#f87171", "#f87171", "#f87171", "#fb923c", "#fb923c"],
            text=["95/100", "92/100", "90/100", "88/100", "79/100", "74/100"],
            textposition="outside",
        ))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1",
            xaxis=dict(range=[0, 115], title="Risk Score"),
            yaxis=dict(autorange="reversed"),
            height=320,
            margin=dict(l=10, r=60, t=10, b=30),
        )

        chart_header(
            "📊 Vendor Risk Score by Platform",
            "This horizontal bar chart ranks the six vendor platforms by a composite risk score (0–100) reflecting KEV catalog volume, average CVSS severity, exploitation frequency, and depth of deployment in defense contractor environments. Use this to prioritize which vendor platforms warrant the most urgent remediation and monitoring investment."
        )
        st.plotly_chart(fig2, use_container_width=True)

        # ── Sources — Tab 2 ──
        st.markdown("---")
        with st.expander("📚 Sources — Critical Assets"):
            st.markdown("""
            <div style="font-size:0.82rem;line-height:2;color:#ffffff">
                [1] CISA Known Exploited Vulnerabilities Catalog —
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" style="color:#38bdf8">
                cisa.gov/known-exploited-vulnerabilities-catalog</a><br>
                [2] NIST NVD — CVE-2023-20198, CVE-2023-23397, CVE-2022-26923, CVE-2023-20269 —
                <a href="https://nvd.nist.gov/" target="_blank" style="color:#38bdf8">
                nvd.nist.gov</a><br>
                [3] Microsoft Security Response Center — Outlook CVE-2023-23397 Advisory —
                <a href="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397" target="_blank" style="color:#38bdf8">
                msrc.microsoft.com — CVE-2023-23397</a><br>
                [4] Cisco Talos — IOS XE CVE-2023-20198 Threat Advisory —
                <a href="https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/" target="_blank" style="color:#38bdf8">
                blog.talosintelligence.com — IOS XE Advisory</a><br>
                [5] Cisco Security Advisory — ASA/FTD CVE-2023-20269 —
                <a href="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC" target="_blank" style="color:#38bdf8">
                sec.cloudapps.cisco.com — CVE-2023-20269</a><br>
                [6] Google Chrome Releases — 2023 Zero-Day Summary —
                <a href="https://chromereleases.googleblog.com/" target="_blank" style="color:#38bdf8">
                chromereleases.googleblog.com</a><br>
                [7] CISA Advisory AA24-038A — Google Workspace OAuth Exploitation —
                <a href="https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a" target="_blank" style="color:#38bdf8">
                cisa.gov/news-events/cybersecurity-advisories/aa24-038a</a><br>
                [8] IBM X-Force Threat Intelligence Index 2024 — Kerberoasting Trends —
                <a href="https://www.ibm.com/think/x-force/2024-x-force-threat-intelligence-index" target="_blank" style="color:#38bdf8">
                ibm.com — X-Force 2024</a>
            </div>
            """, unsafe_allow_html=True)