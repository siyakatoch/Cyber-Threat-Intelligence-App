import streamlit as st
import pandas as pd
import plotly.graph_objects as go


def render():

    # ── CSS (must be inside render, same as dashboard page) ───────────────────
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

    # ══════════════════════════════════════════════════════════════
    # PAGE HEADER
    # ══════════════════════════════════════════════════════════════
    st.markdown('<div class="section-header">🎯 CTI Use Case & Threat Model — Defense Vendor Ecosystem</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box">
    <strong style="color:#38bdf8;font-size:1.05rem">The Problem This Platform Solves</strong><br><br>
    Nation-state actors and ransomware groups rarely attack Lockheed Martin, Boeing, or Leidos directly.
    Instead, they compromise the <strong>technology vendors and managed service providers</strong> those
    organizations depend on — Microsoft 365, Cisco networking equipment, Citrix remote access portals,
    VMware hypervisors, SolarWinds monitoring tools, and Google Cloud services. A single vulnerability
    in a trusted vendor product becomes a master key to hundreds of defense contractors simultaneously.<br><br>
    The SolarWinds SUNBURST compromise is the defining example: Russia's SVR didn't breach the Pentagon —
    they trojanized a software update from a trusted IT monitoring vendor and rode that trust into
    <strong>9 federal agencies and dozens of defense primes</strong> including Booz Allen, SAIC, and Leidos.
    Citrix Bleed gave LockBit access to Boeing. Volt Typhoon lives inside Cisco routers used by
    defense contractors to avoid detection for years.<br><br>
    This CTI platform tracks the <strong>vendor attack surface of the Defense Industrial Base</strong> —
    mapping active adversary campaigns to the specific Microsoft, Cisco, Citrix, VMware, and cloud
    provider vulnerabilities being exploited against defense contractor environments right now.
    </div>
    """, unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════
    # SECTION 1 — WHAT IT ENABLES / WHY THIS ANALYTICS
    # ══════════════════════════════════════════════════════════════
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="sub-header">What Decisions It Enables</div>', unsafe_allow_html=True)
        decisions = [
            ("🔴 Tactical", "Which vendor CVEs in our environment are in the CISA KEV catalog right now? Which Microsoft, Cisco, or Citrix vulnerabilities are being actively exploited against defense contractors? What do we patch or mitigate in the next 24 hours?"),
            ("🟡 Operational", "Which vendor products in our stack are targeted by APT29, Volt Typhoon, or LockBit? Where are our vendor supply chain gaps mapped to CMMC 2.0 controls? What threat-hunting hypotheses should we run against our M365 and cloud environments this week?"),
            ("🟢 Strategic", "Which third-party vendors in our supply chain represent the highest risk to our CUI and program data? How do we meet CMMC SR.3.169 (supply chain risk management) requirements? How do we brief program security officers on vendor-introduced risk?"),
        ]
        for level, desc in decisions:
            st.markdown(f'<div class="info-box"><strong>{level}</strong><br><span style="font-size:0.87rem">{desc}</span></div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="sub-header">Why This Data & Analytics</div>', unsafe_allow_html=True)
        rationale = [
            ("Diamond Models", "Maps real vendor-targeting campaigns (SolarWinds, Citrix Bleed, Cisco SOHO) to the Diamond Model framework — showing exactly how adversaries weaponize trusted vendor products against defense primes."),
            ("Vendor KEV Tracker", "Cross-references CISA Known Exploited Vulnerabilities against Microsoft, Cisco, Citrix, VMware, and Google products actively exploited in DIB environments."),
            ("MITRE ATT&CK Heatmap", "Tactic coverage across DIB-targeting threat actors highlights which vendor exploitation techniques are most frequently used — prioritizing detection in M365, cloud, and network edge environments."),
            ("NIST SP 800-30 / CMMC Risk Table", "Risk scoring tied to CMMC 2.0 supply chain and vendor risk domains (SR, CA, CM) — the controls defense contractors must satisfy for vendor risk management."),
            ("Ransomware Advisory Tracker", "Tracks active CISA StopRansomware advisories specifically tied to vendor CVEs exploited against defense contractors — Citrix Bleed, MOVEit, and network device vulnerabilities."),
        ]
        for title, desc in rationale:
            st.markdown(f'<div class="asset-box"><strong>✦ {title}</strong><br><span style="font-size:0.86rem">{desc}</span></div>', unsafe_allow_html=True)

    st.markdown("---")

    # ══════════════════════════════════════════════════════════════
    # SECTION 2 — KPI SNAPSHOT
    # ══════════════════════════════════════════════════════════════
    st.markdown('<div class="sub-header">📊 Defense Vendor Ecosystem Threat Snapshot (2025)</div>', unsafe_allow_html=True)

    k1, k2, k3, k4 = st.columns(4)
    kpis = [
        ("62%", "DIB Breaches via Third-Party Vendor", "Majority of defense contractor incidents trace to vendor compromise (DCSA, 2024)"),
        ("$2B+", "DPRK IP Theft via Vendor Access", "Targeting vendor tools used by cleared defense firms (DNI, 2026)"),
        ("1,100+", "Active KEV Entries (CISA, 2025)", "Including critical Microsoft, Cisco, Citrix, VMware CVEs targeting DIB"),
        ("72 hrs", "DFARS Incident Reporting Window", "Vendor-caused breaches of CUI trigger mandatory DoD reporting"),
    ]
    for col, (val, label, delta) in zip([k1, k2, k3, k4], kpis):
        with col:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-value">{val}</div>
                <div class="kpi-label">{label}</div>
                <div class="kpi-delta">{delta}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════
    # SECTION 3 — VENDOR KEV TRACKER
    # ══════════════════════════════════════════════════════════════
    st.markdown("---")
    st.markdown('<div class="sub-header">🔍 Vendor KEV Tracker — Actively Exploited Against DIB Environments</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    The following CVEs from key defense contractor technology vendors appear in the
    <strong>CISA Known Exploited Vulnerabilities (KEV) catalog</strong> and have confirmed
    exploitation against defense contractor and government networks. Prioritize patching
    these over non-KEV vulnerabilities per <strong>BOD 22-01</strong>.
    </div>
    """, unsafe_allow_html=True)

    kev_data = {
        "CVE": [
            "CVE-2023-4966", "CVE-2024-20353", "CVE-2024-3400",
            "CVE-2021-44228", "CVE-2023-34362", "CVE-2024-21412",
        ],
        "Vendor / Product": [
            "Citrix NetScaler ADC & Gateway",
            "Cisco ASA / FTD",
            "Palo Alto Networks PAN-OS",
            "Apache Log4j (used across vendor stacks)",
            "Progress MOVEit Transfer",
            "Microsoft Windows SmartScreen",
        ],
        "Vulnerability": [
            "Citrix Bleed — session token hijack, auth bypass",
            "DoS / RCE in remote access VPN",
            "OS command injection in GlobalProtect",
            "Remote code execution (Log4Shell)",
            "SQL injection — file exfiltration",
            "Security feature bypass",
        ],
        "Known DIB Use": [
            "Boeing, defense primes using Citrix for remote access",
            "DIB network perimeter devices — Volt Typhoon pivot",
            "Defense contractor VPN infrastructure",
            "Widespread across defense contractor server stacks",
            "Used by contractors for secure file transfer / CUI",
            "Windows environments across all defense primes",
        ],
        "Exploited By": [
            "LockBit (Boeing 2023)",
            "Volt Typhoon (China)",
            "Nation-state actors",
            "Multiple APTs + ransomware",
            "Cl0p ransomware",
            "APT28 / cybercrime groups",
        ],
        "CMMC Control": [
            "SI.2.214 · CM.2.061",
            "SC.3.177 · CM.2.062",
            "SI.2.214 · CA.2.157",
            "SI.2.214 · CM.2.061",
            "SC.3.177 · IR.2.093",
            "SI.2.214 · CM.2.062",
        ],
    }

    df_kev = pd.DataFrame(kev_data)

    chart_header(
        "📋 Vendor KEV Tracker Table",
        "This table lists vendor CVEs confirmed as actively exploited against defense contractor environments. Each row maps a specific CVE to the vendor product, known DIB use case, threat actor, and CMMC control gap. Use this to identify which vendor vulnerabilities in your stack require immediate patching per BOD 22-01."
    )
    st.dataframe(df_kev, use_container_width=True, hide_index=True, height=260)

    k1c, k2c, k3c = st.columns(3)
    with k1c:
        st.markdown("""
        <div class="info-box" style="text-align:center">
            <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px">CISA KEV Catalog</div>
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank"
               style="font-size:0.78rem;color:#0ea5e9;text-decoration:none;">🔗 Full KEV Catalog</a>
        </div>""", unsafe_allow_html=True)
    with k2c:
        st.markdown("""
        <div class="info-box" style="text-align:center">
            <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px">Microsoft MSRC</div>
            <a href="https://msrc.microsoft.com/update-guide/" target="_blank"
               style="font-size:0.78rem;color:#0ea5e9;text-decoration:none;">🔗 Security Update Guide</a>
        </div>""", unsafe_allow_html=True)
    with k3c:
        st.markdown("""
        <div class="info-box" style="text-align:center">
            <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px">Cisco PSIRT</div>
            <a href="https://sec.cloudapps.cisco.com/security/center/publicationListing.x" target="_blank"
               style="font-size:0.78rem;color:#0ea5e9;text-decoration:none;">🔗 Cisco Security Advisories</a>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════
    # SECTION 4 — THREAT ACTOR PROFILES
    # ══════════════════════════════════════════════════════════════
    st.markdown("---")
    st.markdown('<div class="sub-header">🕵️ Threat Actors — Vendor Exploitation Targeting DIB</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    Select a threat actor to see which <strong>specific vendor products and CVEs</strong> they exploit
    to gain access to defense contractor environments, and the MITRE ATT&CK techniques used.
    </div>
    """, unsafe_allow_html=True)

    actors = {
        "APT29 — Midnight Blizzard (Russia)": {
            "origin": "Russia — SVR (Foreign Intelligence Service)",
            "motivation": "Long-term espionage via trusted vendor products used by defense primes and cleared facilities",
            "targets": "Microsoft 365 and Azure tenants at defense contractors · SolarWinds Orion users (Booz Allen, SAIC, Leidos) · OAuth and cloud identity providers",
            "notable": "SolarWinds SUNBURST (2020): trojanized Orion update reached 18,000 orgs, compromising defense primes via a trusted IT monitoring vendor. Currently targets M365 OAuth tokens, Azure service principals, and MFA gaps at defense contractor cloud tenants per CISA 2025 advisories.",
            "vendor_targets": "SolarWinds Orion · Microsoft 365 · Azure AD · Microsoft Teams · OAuth/SAML identity providers",
            "techniques": [
                "Supply Chain Compromise via Vendor Update [T1195.002]",
                "Valid Accounts — Cloud Accounts [T1078.004]",
                "Forge Web Credentials — SAML Tokens [T1606.002]",
                "Lateral Movement via M365 / Teams [T1021]",
                "Exfiltration via Cloud Storage [T1567.002]",
            ],
        },
        "APT41 — Winnti (China)": {
            "origin": "China — MSS — dual espionage and cybercrime mandate",
            "motivation": "Defense IP theft via exploitation of IT management and development tools used by aerospace and defense manufacturers",
            "targets": "VMware ESXi at defense contractor data centers · Citrix and remote desktop infrastructure · Software development toolchains at defense R&D firms",
            "notable": "DOJ-indicted five members in 2020 for targeting 100+ orgs across defense and aviation. Exploits vendor management interfaces and software supply chain tools to pivot into weapons program R&D environments at Boeing, Northrop Grumman, and defense subcontractors.",
            "vendor_targets": "VMware vSphere / ESXi · Citrix Virtual Apps · JetBrains build tools · GitHub Enterprise · Atlassian Confluence",
            "techniques": [
                "Exploit Public-Facing Application [T1190]",
                "Supply Chain Compromise — Build Tools [T1195.001]",
                "Web Shell on Vendor Management Console [T1505.003]",
                "Credential Dumping from Vendor Admin [T1003]",
                "Data Staged via Vendor Cloud Storage [T1074]",
            ],
        },
        "Volt Typhoon (China)": {
            "origin": "China — PLA / Ministry of State Security",
            "motivation": "Pre-position inside DIB via network edge vendor devices for wartime activation — Taiwan Strait contingency",
            "targets": "Cisco routing and switching equipment at defense contractor facilities · Fortinet and Palo Alto VPN devices · SOHO routers used by remote defense workers",
            "notable": "CISA 2024–2025: Volt Typhoon compromises Cisco, Netgear, and Asus devices used by defense contractors as proxy infrastructure. Lives inside network edge equipment for 5+ years using only native device tools — no malware signature to detect. Specifically targets routers serving defense contractor office locations.",
            "vendor_targets": "Cisco RV320/325 routers · Netgear ProSAFE · Asus routers · Fortinet FortiGate · Ivanti Connect Secure",
            "techniques": [
                "Living-off-the-Land on Vendor Network Devices [T1218]",
                "Valid Vendor Admin Accounts [T1078]",
                "Proxy via Compromised SOHO/Edge Devices [T1090.003]",
                "Network Device CLI for Persistence [T1059.008]",
                "Data Exfiltration via Vendor Management Channel [T1029]",
            ],
        },
        "Lazarus Group (North Korea)": {
            "origin": "North Korea — Reconnaissance General Bureau",
            "motivation": "Steal defense IP and cryptocurrency via vendor software and fake vendor employee schemes",
            "targets": "LinkedIn and job platform impersonation targeting engineers at Boeing, Lockheed, BAE Systems · Fake recruiter campaigns delivering malware via vendor-themed documents",
            "notable": "October 2025: targeted three European defense contractors using fake LinkedIn job offers — malware delivered in vendor-branded documents about drone manufacturing positions (CSIS). Poses as Microsoft, AWS, and defense software vendor recruiters to reach cleared engineers.",
            "vendor_targets": "LinkedIn platform · Microsoft Office macros · AWS job opportunity lures · GitHub repositories · Slack and Teams phishing",
            "techniques": [
                "Spearphishing via Vendor-Branded Documents [T1566.001]",
                "Fake Job Offer via LinkedIn / Teams [T1566]",
                "Malicious Macro in Vendor-Themed Office Doc [T1204.002]",
                "Cryptocurrency Theft via Vendor Wallet Tools [T1657]",
                "Remote Worker Infiltration via Vendor Hiring [T1078.004]",
            ],
        },
        "LockBit / Akira / RansomHub (Ransomware Groups)": {
            "origin": "Non-state criminal ecosystems — Eastern Europe / Russia-nexus RaaS platforms",
            "motivation": "Financial extortion by exploiting unpatched vendor CVEs in defense contractor environments",
            "targets": "Citrix NetScaler at defense primes (Boeing) · MOVEit file transfer at defense suppliers · Unpatched Windows and VMware at Tier 2/3 defense contractors",
            "notable": "LockBit exploited Citrix Bleed (CVE-2023-4966) to breach Boeing October 2023 — a vendor vulnerability in Boeing's Citrix remote access portal. Cl0p exploited MOVEit (CVE-2023-34362) hitting defense contractor file transfer systems. Akira targets unpatched Cisco ASA VPNs at defense suppliers.",
            "vendor_targets": "Citrix NetScaler ADC · Progress MOVEit · Cisco ASA/FTD · VMware ESXi · Windows Server (unpatched)",
            "techniques": [
                "Exploit Vendor CVE for Initial Access [T1190]",
                "Session Token Hijack via Citrix Bleed [T1539]",
                "SQL Injection via MOVEit [T1190]",
                "Data Encrypted for Impact [T1486]",
                "Exfiltration Before Encryption [T1048]",
            ],
        },
    }

    selected_actor = st.selectbox(
        "Select a threat actor to profile:",
        list(actors.keys()),
        key="gov_actor_select"
    )
    a = actors[selected_actor]

    ac1, ac2 = st.columns([1, 1])
    with ac1:
        st.markdown(f"""
        <div class="threat-box">
            <strong style="font-size:1rem;color:#fca5a5;">🔴 {selected_actor}</strong><br><br>
            <strong>Origin:</strong> {a['origin']}<br><br>
            <strong>Motivation:</strong> {a['motivation']}<br><br>
            <strong>Defense Contractor Targets:</strong> {a['targets']}<br><br>
            <strong>Vendor Products Exploited:</strong><br>
            <span style="color:#fde68a;">{a['vendor_targets']}</span><br><br>
            <strong>Notable Activity:</strong><br>{a['notable']}
        </div>
        """, unsafe_allow_html=True)
    with ac2:
        badges = "".join([
            f'<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.35);'
            f'border-radius:8px;padding:0.4rem 0.75rem;margin:0.3rem 0;'
            f'font-family:\'Space Mono\',monospace;font-size:0.75rem;color:#ffffff;">⚡ {t}</div>'
            for t in a["techniques"]
        ])
        st.markdown(f"""
        <div class="info-box">
            <strong>MITRE ATT&CK Techniques:</strong><br><br>
            {badges}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════
    # SECTION 4B — RANSOMWARE ADVISORY TRACKER
    # ══════════════════════════════════════════════════════════════
    st.markdown("---")
    st.markdown('<div class="sub-header">🚨 Ransomware Advisory Tracker — Vendor CVEs Exploited Against DIB</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    Active ransomware advisories tied to <strong>vendor vulnerabilities exploited against defense contractors</strong>,
    cross-referenced against CISA StopRansomware advisories and FBI flash reports.
    Defense contractors face dual exposure: operational disruption <em>and</em> mandatory
    72-hour DoD incident reporting under DFARS 252.204-7012.
    </div>
    """, unsafe_allow_html=True)

    ransomware_data = {
        "Group": ["LockBit 3.0", "Cl0p", "Akira", "RansomHub", "Black Basta"],
        "Vendor CVE Exploited": [
            "CVE-2023-4966 (Citrix Bleed)",
            "CVE-2023-34362 (MOVEit SQL Injection)",
            "CVE-2024-20353 (Cisco ASA/FTD)",
            "CVE-2024-3400 (Palo Alto PAN-OS)",
            "CVE-2021-44228 (Log4Shell)",
        ],
        "Affected Vendor Product": [
            "Citrix NetScaler ADC",
            "Progress MOVEit Transfer",
            "Cisco ASA / FTD VPN",
            "Palo Alto GlobalProtect VPN",
            "Apache Log4j (cross-vendor)",
        ],
        "Known DIB Impact": [
            "Boeing breach Oct 2023 — ~43GB exfiltrated",
            "Defense supplier file transfer systems hit",
            "Defense contractor VPN perimeters targeted",
            "Defense contractor remote access targeted",
            "Widespread across defense contractor servers",
        ],
        "CISA Advisory": ["AA23-325A", "AA23-158A", "AA24-060A", "AA24-242A", "AA21-356A"],
        "CMMC Gap": [
            "IR.2.093 · SI.2.214",
            "SC.3.177 · IR.2.093",
            "AC.2.006 · CM.2.062",
            "SI.2.214 · CA.2.157",
            "CM.2.061 · SI.2.214",
        ],
    }

    df_ransomware = pd.DataFrame(ransomware_data)

    chart_header(
        "📋 Ransomware Advisory Tracker Table",
        "This table maps active ransomware groups to the specific vendor CVEs they exploited against defense contractors, cross-referenced with CISA StopRansomware advisories. Use this to connect a group name to a concrete vendor CVE, CMMC gap, and determine whether the incident triggers mandatory DFARS 72-hour reporting."
    )
    st.dataframe(df_ransomware, use_container_width=True, hide_index=True, height=230)

    st.markdown("""
    <div class="threat-box" style="margin-top:0.5rem">
        <strong style="color:#fca5a5;">📋 DFARS 252.204-7012 — Vendor Breach Reporting Obligation</strong><br>
        <span style="font-size:0.87rem">If a vendor product compromise results in unauthorized access to Covered Defense Information (CDI)
        or CUI on contractor systems, DFARS 252.204-7012 requires reporting to DoD within <strong>72 hours</strong>
        regardless of whether the vulnerability originated in the vendor's product. The contractor — not the vendor —
        bears the reporting obligation.</span>
    </div>
    """, unsafe_allow_html=True)

    ra1, ra2, ra3 = st.columns(3)
    with ra1:
        st.markdown("""<div class="info-box" style="text-align:center">
            <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">CISA StopRansomware</div>
            <a href="https://www.cisa.gov/stopransomware" target="_blank"
               style="font-size:0.78rem;color:#0ea5e9;text-decoration:none;">🔗 cisa.gov/stopransomware</a>
        </div>""", unsafe_allow_html=True)
    with ra2:
        st.markdown("""<div class="info-box" style="text-align:center">
            <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">CISA KEV Catalog</div>
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank"
               style="font-size:0.78rem;color:#0ea5e9;text-decoration:none;">🔗 Known Exploited Vulnerabilities</a>
        </div>""", unsafe_allow_html=True)
    with ra3:
        st.markdown("""<div class="info-box" style="text-align:center">
            <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">FBI Flash Reports</div>
            <a href="https://www.ic3.gov/Media/News/2024" target="_blank"
               style="font-size:0.78rem;color:#0ea5e9;text-decoration:none;">🔗 IC3 / FBI Cyber Alerts</a>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════════
    # SECTION 5 — ATT&CK HEATMAP
    # ══════════════════════════════════════════════════════════════
    st.markdown("---")
    st.markdown('<div class="sub-header">🗺️ MITRE ATT&CK Tactic Coverage — Vendor-Targeting DIB Threat Actors</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    Intensity score (1–5) reflects how frequently each actor exploits vendor products within that
    tactic category against defense contractor environments. <strong>Red = highest vendor exploitation
    exposure</strong> — focus detection engineering on cloud, network edge, and remote access vendor products.
    </div>
    """, unsafe_allow_html=True)

    tactics = ["Recon", "Resource\nDev", "Initial\nAccess", "Execution",
               "Persistence", "Priv\nEscalation", "Defense\nEvasion",
               "Credential\nAccess", "Discovery", "Lateral\nMovement",
               "Collection", "Exfiltration", "Impact"]
    actor_labels = ["APT29 (Russia)", "APT41 (China)", "Volt Typhoon (China)",
                    "Lazarus (DPRK)", "Ransomware Grps"]
    z_data = [
        [2, 3, 4, 3, 4, 3, 4, 4, 3, 4, 4, 4, 1],
        [4, 3, 5, 4, 4, 4, 4, 4, 4, 4, 5, 5, 2],
        [2, 2, 3, 2, 4, 3, 5, 3, 4, 4, 3, 4, 3],
        [3, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4],
        [1, 2, 5, 4, 3, 4, 3, 4, 2, 3, 2, 4, 5],
    ]

    fig_heatmap = go.Figure(data=go.Heatmap(
        z=z_data, x=tactics, y=actor_labels,
        colorscale=[
            [0.0, "#0a1628"], [0.25, "#0f2744"],
            [0.5, "#1e4976"], [0.75, "#0ea5e9"], [1.0, "#f87171"],
        ],
        showscale=True,
        colorbar=dict(
            title=dict(text="Intensity", font=dict(color="#94a3b8")),
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["Rare", "Low", "Moderate", "High", "Critical"],
            tickfont=dict(color="#94a3b8"),
        ),
        hovertemplate="<b>%{y}</b><br>Tactic: %{x}<br>Intensity: %{z}<extra></extra>",
    ))
    fig_heatmap.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cbd5e1", family="DM Sans"),
        margin=dict(t=20, b=20, l=20, r=20), height=290,
        xaxis=dict(tickfont=dict(size=10, color="#94a3b8"), showgrid=False),
        yaxis=dict(tickfont=dict(size=11, color="#94a3b8"), showgrid=False),
    )

    chart_header(
        "🗺️ MITRE ATT&CK Tactic Heatmap",
        "This heatmap shows how frequently each DIB-targeting threat actor exploits vendor products within each ATT&CK tactic category, scored 1–5. Red cells indicate the highest vendor exploitation intensity. Use this to prioritize detection engineering and threat-hunting efforts across M365, cloud, and network edge environments."
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)

    st.markdown("---")

    # ══════════════════════════════════════════════════════════════
    # SECTION 6 — THREAT MODEL TABLE
    # ══════════════════════════════════════════════════════════════
    st.markdown('<div class="sub-header">🧩 Vendor Risk Threat Model — NIST SP 800-30 Risk Assessment</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    Each scenario represents a <strong>vendor product being exploited against a defense contractor</strong>.
    Scored using <strong>NIST SP 800-30</strong>: Risk Score = Likelihood (1–5) × Impact (1–5).&nbsp;
    <span style="color:#f87171;">■ Critical ≥ 16</span> &nbsp;
    <span style="color:#fde68a;">■ Medium 10–15</span> &nbsp;
    <span style="color:#6ee7b7;">■ Managed &lt; 10</span>
    </div>
    """, unsafe_allow_html=True)

    threat_data = {
        "Threat Scenario": [
            "Microsoft 365 / Azure Credential Compromise at Defense Contractor",
            "SolarWinds-Style Supply Chain via Trusted Vendor Update",
            "Citrix NetScaler Exploit — Remote Access Breach (CVE-2023-4966)",
            "Cisco Router Compromise — Volt Typhoon Pre-Positioning",
            "MOVEit File Transfer Exploit — CUI Exfiltration (CVE-2023-34362)",
            "VMware ESXi Ransomware — Defense Contractor Data Center",
            "Palo Alto PAN-OS Exploit — VPN Gateway Breach (CVE-2024-3400)",
            "Fake Vendor Recruiter — Cleared Engineer Phishing (DPRK)",
            "Log4Shell Across Vendor-Supplied Server Stack (CVE-2021-44228)",
            "Google Workspace Misconfiguration Exposing CUI",
        ],
        "Primary Actor": [
            "APT29 (Russia)", "APT29 / APT41",
            "LockBit / Ransomware Groups", "Volt Typhoon (China)",
            "Cl0p Ransomware", "Ransomware Groups",
            "Nation-State / RansomHub", "Lazarus Group (DPRK)",
            "Multiple APTs + Ransomware", "Insider / APT41",
        ],
        "Vendor": [
            "Microsoft", "SolarWinds / Any IT Vendor",
            "Citrix", "Cisco",
            "Progress Software", "VMware (Broadcom)",
            "Palo Alto Networks", "LinkedIn / Microsoft Teams",
            "Apache (cross-vendor)", "Google",
        ],
        "Likelihood": [5, 4, 4, 4, 4, 4, 3, 4, 4, 3],
        "Impact":     [5, 5, 4, 5, 4, 4, 4, 4, 4, 4],
        "FISMA Control": [
            "IA-2 MFA / AC-17", "SA-12 Supply Chain",
            "SI-2 Patching / RA-5", "SC-7 Boundary / CA-8",
            "SI-2 Patching / SC-28", "CP-9 Backup / IR-4",
            "SI-2 Patching / RA-5", "AT-2 Training / IA-2",
            "SI-2 Patching / CM-6", "AC-3 Access / SC-28",
        ],
        "CMMC 2.0 Domain": [
            "IA.3.083 · AC.2.006", "SR.3.169 · CM.2.061",
            "SI.2.214 · CA.2.157", "SC.3.177 · CA.3.161",
            "SC.3.177 · IR.2.093", "IR.2.093 · CA.2.158",
            "SI.2.214 · AC.2.006", "AT.2.056 · IA.3.083",
            "CM.2.061 · SI.2.214", "AC.2.007 · SC.3.177",
        ],
    }

    df = pd.DataFrame(threat_data)
    df["Risk Score"] = df["Likelihood"] * df["Impact"]

    def color_risk(val):
        if val >= 16:
            return "color: #f87171; font-weight: bold;"
        elif val >= 10:
            return "color: #fde68a; font-weight: bold;"
        return "color: #6ee7b7; font-weight: bold;"

    chart_header(
        "🧩 NIST SP 800-30 Threat Model Table",
        "This table scores 10 vendor exploitation scenarios using NIST SP 800-30 — Risk Score = Likelihood × Impact. Red scores (≥16) represent critical vendor risk requiring immediate action. Use this to prioritize which vendor threats to brief to leadership and map to CMMC and FISMA control gaps."
    )
    st.dataframe(
        df.style.map(color_risk, subset=["Risk Score"]),
        use_container_width=True, hide_index=True, height=415,
    )

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="sub-header">📈 Risk Matrix — Likelihood vs. Impact</div>', unsafe_allow_html=True)

    df["Risk Level"] = pd.cut(df["Risk Score"], bins=[0, 9, 15, 25],
                               labels=["Managed", "Medium", "Critical"])
    color_map = {"Managed": "#34d399", "Medium": "#fbbf24", "Critical": "#f87171"}

    fig_scatter = go.Figure()
    for level, color in color_map.items():
        sub = df[df["Risk Level"] == level]
        if sub.empty:
            continue
        fig_scatter.add_trace(go.Scatter(
            x=sub["Likelihood"], y=sub["Impact"],
            mode="markers+text", name=level,
            marker=dict(size=20, color=color, opacity=0.85,
                        line=dict(width=1, color="#0a1628")),
            text=sub["Threat Scenario"].apply(lambda x: x[:28] + "…" if len(x) > 28 else x),
            textposition="top center",
            textfont=dict(size=9, color="#cbd5e1"),
            hovertemplate="<b>%{text}</b><br>Likelihood: %{x}<br>Impact: %{y}<extra></extra>",
        ))

    fig_scatter.add_shape(type="rect", x0=3.5, y0=3.5, x1=5.4, y1=5.4,
        fillcolor="rgba(239,68,68,0.07)",
        line=dict(color="rgba(239,68,68,0.25)", width=1))
    fig_scatter.add_shape(type="rect", x0=0.6, y0=0.6, x1=3.5, y1=3.5,
        fillcolor="rgba(52,211,153,0.05)",
        line=dict(color="rgba(52,211,153,0.2)", width=1))
    fig_scatter.add_annotation(x=4.6, y=5.25, text="⚠ CRITICAL ZONE",
        showarrow=False, font=dict(color="#f87171", size=10, family="Space Mono"))
    fig_scatter.add_annotation(x=1.4, y=0.75, text="✓ MANAGED ZONE",
        showarrow=False, font=dict(color="#34d399", size=10, family="Space Mono"))

    fig_scatter.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,22,40,0.6)",
        font=dict(color="#cbd5e1", family="DM Sans"),
        xaxis=dict(title="Likelihood →", range=[0.5, 5.5],
                   gridcolor="#1e3a5f", tickfont=dict(color="#94a3b8")),
        yaxis=dict(title="Impact →", range=[0.5, 5.5],
                   gridcolor="#1e3a5f", tickfont=dict(color="#94a3b8")),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#94a3b8")),
        margin=dict(t=30, b=40, l=40, r=20), height=470,
    )

    chart_header(
        "📈 Risk Matrix — Likelihood vs. Impact",
        "This scatter plot visualizes the 10 threat scenarios from the table above, plotting each by Likelihood vs. Impact. Points in the upper-right critical zone represent the highest-priority vendor risks. Use this to quickly communicate vendor risk posture to non-technical stakeholders and leadership."
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

    st.markdown("---")

    # ══════════════════════════════════════════════════════════════
    # SECTION 7 — CTI LIFECYCLE
    # ══════════════════════════════════════════════════════════════
    st.markdown('<div class="sub-header">🔄 CTI Intelligence Lifecycle — Defense Vendor Risk Application</div>', unsafe_allow_html=True)
    gov_lifecycle = [
        ("🧭", "Direction", "Define PIRs around vendor products in scope: which Microsoft, Cisco, Citrix, VMware, and cloud services touch CUI? Map vendor stack to CMMC SR domain requirements."),
        ("📡", "Collection", "CISA KEV catalog, CISA StopRansomware advisories, Microsoft MSRC, Cisco PSIRT, Palo Alto Unit 42, Google Project Zero, FBI flash reports, DCSA vendor threat reporting."),
        ("⚙️", "Processing", "Cross-reference vendor CVEs against CISA KEV. Map exploited CVEs to CMMC control gaps. Correlate vendor security bulletins with active DIB-targeting threat actor TTPs."),
        ("🧠", "Analysis", "Score vendor risk per NIST SP 800-30. Map exploited vendor TTPs to MITRE ATT&CK. Identify which contractor vendor products are in the critical zone. Produce finished intel for FSO and ISSO."),
        ("📤", "Dissemination", "KEV patch mandates to IT/operations; vendor TTP alerts to SOC and threat hunters; CMMC vendor gap reports to compliance; strategic vendor risk briefings to CISO and program managers."),
        ("🔄", "Feedback", "Track vendor patch compliance. Update vendor risk scores after CMMC assessments. New vendor CVEs and CISA advisories feed back into collection requirements and detection rules."),
    ]
    gov_cols = st.columns(6)
    for col, (icon, phase, desc) in zip(gov_cols, gov_lifecycle):
        with col:
            st.markdown(f"""
            <div style="background:rgba(14,165,233,0.08);border:1px solid rgba(56,189,248,0.2);
                        border-radius:10px;padding:0.8rem;text-align:center;min-height:175px">
                <div style="font-size:1.5rem">{icon}</div>
                <div style="font-family:'Space Mono',monospace;font-size:0.72rem;color:#38bdf8;
                            text-transform:uppercase;letter-spacing:0.05em;margin:0.3rem 0">{phase}</div>
                <div style="font-size:0.74rem;color:#ffffff;line-height:1.4">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # ══════════════════════════════════════════════════════════════
    # SOURCES (expandable)
    # ══════════════════════════════════════════════════════════════
    with st.expander("📚 Sources & References", expanded=False):
        sources = [
            {
                "label": "CISA Known Exploited Vulnerabilities (KEV) Catalog",
                "desc": "Authoritative catalog of CVEs actively exploited in the wild. Primary source for all vendor CVEs in the KEV tracker and threat model table, including Citrix Bleed, MOVEit, Cisco ASA, and Palo Alto entries.",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "apa": "Cybersecurity and Infrastructure Security Agency. (2025). <em>Known exploited vulnerabilities catalog.</em> CISA. https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            },
            {
                "label": "CISA StopRansomware — LockBit AA23-325A · Cl0p AA23-158A · Akira AA24-060A · RansomHub AA24-242A",
                "desc": "CISA joint advisories for ransomware groups exploiting vendor CVEs against defense contractor environments. Source for all CISA advisory numbers in the ransomware tracker.",
                "url": "https://www.cisa.gov/stopransomware",
                "apa": "Cybersecurity and Infrastructure Security Agency. (2023–2024). <em>StopRansomware advisories.</em> CISA. https://www.cisa.gov/stopransomware",
            },
            {
                "label": "CISA — Volt Typhoon Joint Advisory (AA24-038A) — Cisco Device Exploitation",
                "desc": "Joint CISA/NSA/FBI advisory confirming Volt Typhoon's exploitation of Cisco and SOHO network devices for pre-positioning inside defense contractor networks. Primary source for Volt Typhoon vendor targeting.",
                "url": "https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors",
                "apa": "CISA, NSA, & FBI. (2024). <em>People's Republic of China state-sponsored cyber actor living off the land.</em> CISA Advisory AA24-038A.",
            },
            {
                "label": "Microsoft Security Response Center (MSRC) — Security Update Guide",
                "desc": "Microsoft's official security advisory feed. Source for M365, Azure AD, and Windows vulnerability context referenced in the threat actor profiles and KEV tracker.",
                "url": "https://msrc.microsoft.com/update-guide/",
                "apa": "Microsoft Corporation. (2025). <em>Security update guide.</em> Microsoft Security Response Center. https://msrc.microsoft.com/update-guide/",
            },
            {
                "label": "Cisco PSIRT — Security Advisories (CVE-2024-20353, CVE-2024-20359)",
                "desc": "Cisco Product Security Incident Response Team advisories for Cisco ASA and FTD vulnerabilities exploited by Volt Typhoon and ransomware groups against defense contractor network perimeters.",
                "url": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
                "apa": "Cisco Systems. (2024). <em>Cisco security advisories.</em> Cisco PSIRT. https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
            },
            {
                "label": "DoD CMMC 2.0 — Supply Chain Risk Management (SR Domain)",
                "desc": "DoD CMMC 2.0 framework. Source for all SR, CA, CM, IR, and SC domain control mappings in the threat model table.",
                "url": "https://dodcio.defense.gov/CMMC/",
                "apa": "U.S. Department of Defense. (2024). <em>Cybersecurity Maturity Model Certification (CMMC) 2.0.</em> DoD CIO. https://dodcio.defense.gov/CMMC/",
            },
            {
                "label": "DFARS 252.204-7012 — Safeguarding Covered Defense Information",
                "desc": "DFARS clause requiring 72-hour DoD cyber incident reporting for vendor-caused breaches affecting covered defense information.",
                "url": "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting.",
                "apa": "Department of Defense. (2023). <em>DFARS 252.204-7012.</em> acquisition.gov.",
            },
            {
                "label": "FireEye / Mandiant — SUNBURST Backdoor Analysis (Dec 2020)",
                "desc": "Original disclosure of the SolarWinds SUNBURST supply chain attack. Source for vendor-targeting context in threat actor profiles.",
                "url": "https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor",
                "apa": "FireEye. (2020, December 13). <em>Highly evasive attacker leverages SolarWinds supply chain.</em> Mandiant.",
            },
            {
                "label": "CSIS — Significant Cyber Incidents (2022–Dec 2025)",
                "desc": "Source for Boeing/LockBit October 2023 incident, Lazarus Group defense contractor targeting October 2025, and vendor-related breach incident context throughout this page.",
                "url": "https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents",
                "apa": "Center for Strategic and International Studies. (2025). <em>Significant cyber incidents.</em> CSIS.",
            },
            {
                "label": "MITRE ATT&CK — APT29 (G0016), APT41 (G0096), Volt Typhoon Group Profiles",
                "desc": "MITRE ATT&CK group profiles for all threat actors on this page. Source for TTP mappings, technique IDs, and vendor-specific exploitation techniques.",
                "url": "https://attack.mitre.org/groups/",
                "apa": "MITRE Corporation. (2025). <em>ATT&CK Groups.</em> MITRE ATT&CK. https://attack.mitre.org/groups/",
            },
            {
                "label": "DNI — 2026 Annual Threat Assessment",
                "desc": "Source for DPRK $2B+ figure, China and Russia as most persistent vendor-targeting threats against DIB, and AI-accelerated vendor exploitation forecasts.",
                "url": "https://www.dni.gov/index.php/newsroom/press-releases/press-releases-2026/4142-pr-03-26",
                "apa": "Office of the Director of National Intelligence. (2026). <em>Annual threat assessment of the U.S. intelligence community.</em> ODNI.",
            },
        ]

        for s in sources:
            st.markdown(f"""
            <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                        border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                        padding:0.85rem 1.1rem;margin:0.5rem 0;">
                <div style="font-family:'Space Mono',monospace;font-size:0.8rem;
                            color:#38bdf8;margin-bottom:0.3rem;">
                    📄 {s['label']}
                </div>
                <div style="font-size:0.84rem;color:#94a3b8;margin-bottom:0.4rem;">{s['desc']}</div>
                <div style="font-size:0.78rem;color:#64748b;font-style:italic;
                            margin-bottom:0.35rem;">{s['apa']}</div>
                <a href="{s['url']}" target="_blank"
                   style="font-size:0.76rem;color:#0ea5e9;text-decoration:none;">🔗 {s['url']}</a>
            </div>
            """, unsafe_allow_html=True)