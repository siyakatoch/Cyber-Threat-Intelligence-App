import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def render():
    st.markdown('<div class="section-header">Introduction & Industry Background</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box" style="color:#ffffff">
    This platform focuses on <strong>cyber vulnerabilities in commercial vendor products</strong> — 
    specifically Microsoft, Cisco, and Google — as they affect major defense contractors like 
    Lockheed Martin, Boeing, and Leidos. Defense contractors don't operate on isolated systems; 
    they rely on the same commercial platforms as the rest of the enterprise world. When critical 
    vulnerabilities emerge in those products, the exposure flows directly into the 
    <strong>Defense Industrial Base (DIB)</strong> — threatening classified-adjacent networks, 
    controlled unclassified information (CUI), and weapons program data.
    </div>
    """, unsafe_allow_html=True)

    # ── Platform Focus ──
    st.markdown('<div class="sub-header">What This Platform Covers</div>', unsafe_allow_html=True)
    cols = st.columns(3)
    focus = [
        ("🏭 Defense Contractors", "Lockheed Martin, Boeing, and Leidos — prime contractors whose operations depend on commercial vendor platforms for daily work, secure communications, and program management."),
        ("🔌 Commercial Vendors", "Microsoft, Cisco, and Google — whose products (Active Directory, Exchange, IOS XE, ASA, Chrome, Workspace) are embedded across contractor environments and are actively targeted by adversaries."),
        ("📋 Vulnerability Data", "CVEs sourced from the CISA Known Exploited Vulnerabilities (KEV) catalog, with CVSS scores from NIST NVD and vendor advisories (Microsoft MSRC, Cisco PSIRT, Google Security Blog)."),
    ]
    for i, (title, desc) in enumerate(focus):
        with cols[i]:
            st.markdown(f'<div class="info-box"><strong style="color:#ffffff">{title}</strong><br><span style="font-size:0.85rem;color:#ffffff">{desc}</span></div>', unsafe_allow_html=True)

    # ── Why This Matters ──
    st.markdown('<div class="sub-header">Why Vendor Vulnerabilities Matter for Defense</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box" style="color:#ffffff;margin-bottom:1rem">
    Defense contractors are high-value targets for nation-state actors, ransomware groups, and 
    cyber criminals. But the attack surface isn't just classified networks — it's the commercial 
    off-the-shelf (COTS) software and hardware running alongside them. A single unpatched 
    vulnerability in Microsoft Exchange or a Cisco VPN appliance can give an adversary 
    authenticated access to a contractor's entire environment, including CUI repositories, 
    program schedules, and engineering systems. This platform surfaces exactly those risks — 
    mapped to real CVEs, real CVSS scores, and real exploitation confirmed by CISA.
    </div>
    """, unsafe_allow_html=True)

    # ── KPI Cards ──
    st.markdown('<div class="sub-header">Platform Scope at a Glance</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="kpi-card"><div class="kpi-value">3</div><div class="kpi-label">Vendors Tracked</div><div class="kpi-delta">Microsoft, Cisco, Google</div></div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="kpi-card"><div class="kpi-value">3</div><div class="kpi-label">Defense Contractors</div><div class="kpi-delta">Lockheed, Boeing, Leidos</div></div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="kpi-card"><div class="kpi-value">CISA KEV</div><div class="kpi-label">Primary Data Source</div><div class="kpi-delta">Confirmed exploited CVEs</div></div>', unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="kpi-card"><div class="kpi-value">CVSS</div><div class="kpi-label">Severity Scoring</div><div class="kpi-delta">NIST NVD + Vendor Advisories</div></div>', unsafe_allow_html=True)

    # ── Vendor Overview Table ──
    st.markdown('<div class="sub-header">Vendors & Products in Scope</div>', unsafe_allow_html=True)
    vendors = {
        "Vendor": [
            "Microsoft", "Microsoft", "Microsoft",
            "Cisco", "Cisco",
            "Google", "Google",
        ],
        "Product": [
            "Active Directory / Entra ID",
            "Exchange / M365 GCC High",
            "Windows OS / Azure",
            "IOS XE (Routers & Switches)",
            "ASA / Firepower VPN",
            "Chrome Browser",
            "Google Workspace",
        ],
        "Role in Contractor Environment": [
            "Identity & access management backbone",
            "Email & collaboration for cleared employees",
            "Endpoint OS & cloud infrastructure",
            "Campus network infrastructure",
            "Remote access VPN for cleared workforce",
            "Primary browser for GCC High & web tools",
            "Unclassified collaboration & document sharing",
        ],
        "Example CVE": [
            "CVE-2022-26923 (CVSS 8.8)",
            "CVE-2023-23397 (CVSS 9.8)",
            "CVE-2024-21410 (CVSS 9.8)",
            "CVE-2023-20198 (CVSS 10.0)",
            "CVE-2023-20269 (CVSS 9.8)",
            "CVE-2023-4863 (CVSS 8.8)",
            "OAuth Misconfiguration (CISA AA24-038A)",
        ],
        "In CISA KEV": [
            "✅ Yes", "✅ Yes", "✅ Yes",
            "✅ Yes", "✅ Yes",
            "✅ Yes", "✅ Yes",
        ],
    }
    st.dataframe(pd.DataFrame(vendors), use_container_width=True, hide_index=True)

    # ── Why CTI for This Scope ──
    st.markdown('<div class="sub-header">Why Cyber Threat Intelligence for Vendor Risk?</div>', unsafe_allow_html=True)
    points = [
        "CISA KEV Catalog: Every CVE in this platform is confirmed exploited in the wild — not theoretical. CISA mandates federal agencies remediate KEV entries within strict deadlines, and defense contractors operating under DFARS follow the same requirements.",
        "CVSS Scoring: CVSS scores from NIST NVD and vendor advisories (Microsoft MSRC, Cisco PSIRT, Google Security Blog) provide a standardized severity baseline for prioritizing which vulnerabilities pose the greatest risk to contractor environments.",
        "Vendor Concentration Risk: Microsoft, Cisco, and Google products are deployed across virtually every defense contractor environment. A single critical CVE in any of these platforms creates sector-wide exposure simultaneously.",
        "Nation-State Exploitation: Adversaries including Volt Typhoon, APT28, and HAFNIUM have specifically exploited vulnerabilities in these vendor platforms to gain persistent access to defense contractor networks — as documented in CISA advisories.",
        "Patch Prioritization: Defense contractors running legacy systems or operating under strict change control windows face extended exposure. CTI helps security teams prioritize which patches matter most given their specific vendor stack.",
        "Compliance & Reporting: DFARS 252.204-7012 requires contractors to report cyber incidents within 72 hours. Understanding which vendor CVEs are actively exploited informs both incident response and proactive compliance posture.",
    ]
    for pt in points:
        st.markdown(f'<div class="info-box" style="color:#ffffff">✦ {pt}</div>', unsafe_allow_html=True)

    # ── Sources (expandable) ──
    with st.expander("📚 Sources & References", expanded=False):
        sources = [
            {
                "label": "CISA Known Exploited Vulnerabilities Catalog",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            },
            {
                "label": "NIST National Vulnerability Database (NVD)",
                "url": "https://nvd.nist.gov/",
            },
            {
                "label": "Microsoft Security Response Center (MSRC)",
                "url": "https://msrc.microsoft.com/update-guide/",
            },
            {
                "label": "Cisco Security Advisories (PSIRT)",
                "url": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
            },
            {
                "label": "Google Security Blog & Chrome Releases",
                "url": "https://security.googleblog.com/",
            },
            {
                "label": "CISA Advisory AA24-038A — Volt Typhoon & Critical Infrastructure",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a",
            },
            {
                "label": "DFARS 252.204-7012 — Safeguarding Covered Defense Information",
                "url": "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting.",
            },
        ]
        for s in sources:
            st.markdown(f"""
            <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                        border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                        padding:0.85rem 1.1rem;margin:0.5rem 0;">
                <div style="font-family:'Space Mono',monospace;font-size:0.8rem;color:#38bdf8;margin-bottom:0.3rem;">
                        📄 {s['label']}
                </div>
                <a href="{s['url']}" target="_blank"
                    style="font-size:0.76rem;color:#0ea5e9;text-decoration:none;">🔗 {s['url']}</a>
            </div>
            """, unsafe_allow_html=True)