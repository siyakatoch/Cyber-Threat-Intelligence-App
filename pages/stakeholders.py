import streamlit as st
import pandas as pd


def render():
    st.markdown('<div class="section-header">👥 Stakeholders & User Stories</div>', unsafe_allow_html=True)

    tab_stakeholders, tab_role_based = st.tabs([
        "Stakeholders",
        "Role-Based View",
    ])

    # ─────────────────────────────────────────────────────────────
    # TAB 1 — STAKEHOLDERS & USER STORIES
    # ─────────────────────────────────────────────────────────────
    with tab_stakeholders:
        st.markdown("""
        <div class="info-box">
            This platform serves three key stakeholders at defense contractors like Lockheed Martin, Boeing,
            and Leidos — each with distinct responsibilities for managing vendor cybersecurity risk.
            All three rely on the same underlying data: CVEs from the CISA Known Exploited Vulnerabilities
            (KEV) catalog, CVSS scores from NIST NVD and vendor advisories, and exploitation timelines
            across Microsoft, Cisco, and Google products.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        personas = [
            {
                "icon": "🔐",
                "name": "Security Operations & Threat Analysts",
                "color_bg":     "rgba(14,165,233,0.06)",
                "color_border": "rgba(56,189,248,0.2)",
                "color_accent": "#38bdf8",
                "color_dim":    "rgba(56,189,248,0.18)",
                "examples": ["SOC Analysts", "Vulnerability Management Teams", "Threat Intelligence Analysts"],
                "description": (
                    "The day-to-day defenders responsible for monitoring, triaging, and remediating "
                    "vulnerabilities across the contractor's vendor stack. They need to know which CVEs "
                    "are actively exploited, how severe they are, and how fast adversaries are weaponizing them."
                ),
                "stories": [
                    ("Prioritize Patching by Confirmed Exploitation",
                    "As a SOC analyst, I want to see which Microsoft, Cisco, and Google CVEs are in the "
                    "CISA KEV catalog so I can prioritize patching based on confirmed exploitation rather "
                    "than theoretical risk."),
                    ("Filter by Vendor & CVSS Score",
                    "As a vulnerability management analyst, I want to filter CVEs by vendor and CVSS score "
                    "so I can quickly identify the highest-severity vulnerabilities affecting our specific infrastructure."),
                ],
                "features": ["CVE table filtered by CISA KEV status", "KEV exploitation timeline chart"],
            },
            {
                "icon": "💼",
                "name": "IT & Network Infrastructure Teams",
                "color_bg":     "rgba(52,211,153,0.06)",
                "color_border": "rgba(52,211,153,0.2)",
                "color_accent": "#34d399",
                "color_dim":    "rgba(52,211,153,0.18)",
                "examples": ["Network Engineers", "System Administrators", "Cloud & Identity Teams"],
                "description": (
                    "The teams directly managing Microsoft Active Directory, Cisco network infrastructure, "
                    "and Google Workspace environments inside contractor facilities. They are responsible for "
                    "applying patches, configuring systems securely, and responding to vendor advisories."
                ),
                "stories": [
                    ("Understand Exploitation Timelines for Cisco Devices",
                    "As a network engineer managing Cisco IOS XE devices, I want to see exploitation timelines "
                    "for Cisco CVEs so I can understand how quickly I need to act after a vulnerability is disclosed."),
                    ("Escalate Critical AD Vulnerabilities with Data",
                    "As a system administrator managing Microsoft Active Directory, I want to view high-severity "
                    "AD vulnerabilities with CVSS scores so I can escalate the most critical issues to leadership "
                    "with data to back it up."),
                ],
                "features": ["CVSS score distribution by vendor", "Sources section with direct advisory links"],
            },
            {
                "icon": "📊",
                "name": "CISOs & Security Leadership",
                "color_bg":     "rgba(168,85,247,0.06)",
                "color_border": "rgba(192,132,252,0.2)",
                "color_accent": "#a855f7",
                "color_dim":    "rgba(192,132,252,0.18)",
                "examples": ["Chief Information Security Officer (CISO)", "VP of Cybersecurity", "Program Security Officers (PSOs)"],
                "description": (
                    "Executive and senior leadership responsible for security strategy, compliance, and "
                    "investment decisions. They need a high-level view of vendor risk exposure to justify "
                    "budget, demonstrate compliance with DFARS requirements, and present risk posture to "
                    "boards and program offices."
                ),
                "stories": [
                    ("Build a Data-Driven Patch Prioritization Case",
                    "As a CISO, I want to see a summary of critical vendor CVEs affecting our environment "
                    "so I can build a data-driven case for prioritizing patch management resources across "
                    "Microsoft, Cisco, and Google platforms."),
                    ("Justify CTI Investment to the Board",
                    "As a security leader, I want to view breach cost data and CVSS severity distributions "
                    "so I can demonstrate the financial risk of unpatched vendor vulnerabilities and justify "
                    "CTI platform investment to the board."),
                ],
                "features": ["KPI summary cards & risk score chart", "Intelligence Buy-In page"],
            },
        ]

        for p in personas:
            st.markdown(f"""
            <div style="background:{p['color_bg']};border:1px solid {p['color_border']};
                        border-left:4px solid {p['color_accent']};border-radius:0 12px 12px 0;
                        padding:1.2rem 1.5rem;margin-bottom:1rem;">
                <div style="font-family:'Space Mono',monospace;font-size:1rem;font-weight:700;
                            color:{p['color_accent']};margin-bottom:0.4rem;">
                    {p['icon']} {p['name']}
                </div>
                <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:0.6rem;">
                    {p['description']}
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:0.4rem;
                        color:{p["color_accent"]};border-radius:6px;
                        font-size:0.9rem;font-family:'Space Mono',monospace;">Persona Examples:
                    {''.join(f'''<span style="background:{p["color_bg"]};border:1px solid {p["color_dim"]};
                        color:{p["color_accent"]};border-radius:6px;padding:0.15rem 0.6rem;
                        font-size:0.72rem;font-family:'Space Mono',monospace;">{ex}</span>'''
                        for ex in p['examples'])}
                </div>
            </div>
            """, unsafe_allow_html=True)

            c1, c2 = st.columns(2)

            with c1:
                st.markdown('<div class="sub-header">📋 User Stories</div>', unsafe_allow_html=True)
                for title, story in p["stories"]:
                    st.markdown(f"""
                    <div style="background:{p['color_bg']};border:1px solid {p['color_dim']};
                                border-radius:10px;padding:0.9rem 1.1rem;margin:0.4rem 0;">
                        <div style="font-size:0.78rem;font-weight:700;color:{p['color_accent']};
                                    margin-bottom:0.3rem;text-transform:uppercase;letter-spacing:0.05em;">
                            {title}
                        </div>
                        <div style="font-size:0.82rem;color:#94a3b8;line-height:1.55;">
                            "{story}"
                        </div>
                    </div>""", unsafe_allow_html=True)

            with c2:
                st.markdown('<div class="sub-header">🖥️ Platform Features Used</div>', unsafe_allow_html=True)
                for feature in p["features"]:
                    st.markdown(f"""
                    <div style="display:flex;align-items:center;gap:0.75rem;
                                padding:0.6rem 0;border-bottom:1px solid #1e293b;">
                        <span style="color:{p['color_accent']};font-size:0.9rem;">→</span>
                        <span style="font-size:0.82rem;color:#94a3b8;">{feature}</span>
                    </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

        # ── Sources (expandable) ──────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📚 Sources & References", expanded=False):
            for label, url in [
                ("CISA Known Exploited Vulnerabilities Catalog",        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("NIST National Vulnerability Database (NVD)",          "https://nvd.nist.gov/"),
                ("Microsoft Security Response Center (MSRC)",           "https://msrc.microsoft.com/update-guide/"),
                ("Cisco Security Advisories (PSIRT)",                   "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
                ("DFARS 252.204-7012 — Safeguarding Covered Defense Information", "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting."),
                ("IBM X-Force Threat Intelligence Index 2024",          "https://www.ibm.com/think/x-force/2024-x-force-threat-intelligence-index"),
            ]:
                st.markdown(f"""
                <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                            border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                            padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.76rem;
                                color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank"
                    style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)


    # ─────────────────────────────────────────────────────────────
    # TAB 2 — ROLE-BASED VIEW
    # ─────────────────────────────────────────────────────────────
    with tab_role_based:

        st.markdown("""
        <div class="info-box">
            Select your role below to see a tailored view of the platform — from high-level executive
            summaries to deep technical analyst drill-downs. Each view surfaces the same underlying data
            through the lens of what matters most to that audience.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Role selector ─────────────────────────────────────────────────────
        role = st.radio(
            "👤 Select Your Role",
            options=[
                "📊 Executive Summary  —  CISOs & Security Leadership",
                "🔐 Analyst Drill-Down  —  SOC & Threat Intelligence",
                "💼 Operations View  —  IT & Network Infrastructure",
            ],
            horizontal=True,
            key="role_selector",
        )

        st.markdown("---")

        # ══════════════════════════════════════════════════════════════════════
        # ROLE 1 — EXECUTIVE SUMMARY
        # ══════════════════════════════════════════════════════════════════════
        if "Executive" in role:

            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.3rem;font-weight:700;
                        color:#a855f7;margin-bottom:0.2rem;">📊 Executive Summary</div>
            <div style="font-size:0.82rem;color:#64748b;margin-bottom:1.2rem;">
                Strategic risk posture overview for CISOs, VPs, and Program Security Officers.
                Focused on business impact, compliance exposure, and investment justification.
            </div>
            """, unsafe_allow_html=True)

            # KPI cards
            k1, k2, k3, k4 = st.columns(4)
            kpis = [
                ("100", "KEV CVEs Tracked", "#a855f7", "Active in catalog"),
                ("67%", "Critical or High", "#ef4444", "Require immediate action"),
                ("34", "Ransomware-Linked", "#f97316", "Known ransomware vectors"),
                ("3", "Vendors in Scope", "#38bdf8", "Microsoft · Cisco · Google"),
            ]
            for col, (val, label, color, sub) in zip([k1, k2, k3, k4], kpis):
                col.markdown(f"""
                <div style="background:rgba(0,0,0,0.2);border:1px solid {color}33;
                            border-top:3px solid {color};border-radius:10px;
                            padding:1rem 1.1rem;text-align:center;">
                    <div style="font-family:'Space Mono',monospace;font-size:1.8rem;
                                font-weight:700;color:{color};line-height:1.1;">{val}</div>
                    <div style="font-size:0.7rem;color:#94a3b8;text-transform:uppercase;
                                letter-spacing:0.07em;margin-top:0.3rem;">{label}</div>
                    <div style="font-size:0.68rem;color:#475569;margin-top:0.2rem;">{sub}</div>
                </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Strategic risk narrative
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1rem;font-weight:700;
                        color:#a855f7;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">🏛️ Strategic Risk Narrative</div>
            """, unsafe_allow_html=True)

            risk_items = [
                ("🔴", "Critical Compliance Exposure",
                 "34% of tracked CVEs have confirmed ransomware associations, directly implicating "
                 "DFARS 252.204-7012 incident reporting obligations. Unpatched systems risk contract "
                 "suspension and CUI spillage liability."),
                ("🟠", "Vendor Concentration Risk",
                 "Microsoft accounts for the largest share of critical CVEs, with Active Directory and "
                 "Exchange Server vulnerabilities frequently exploited in APT campaigns targeting "
                 "defense contractors. Single-vendor dependency amplifies blast radius."),
                ("🟡", "Patch Window Compression",
                 "Mean time from CVE disclosure to active exploitation has compressed to under 15 days "
                 "for critical vulnerabilities. Traditional monthly patch cycles are no longer sufficient "
                 "for KEV-listed items under BOD 22-01."),
                ("🟢", "Remediation ROI",
                 "Prioritizing the top 20 Critical/Ransomware-linked CVEs addresses the highest-probability "
                 "breach vectors with focused resource investment — estimated to reduce exposure by over 60% "
                 "of the current risk surface."),
            ]

            for dot, title, body in risk_items:
                st.markdown(f"""
                <div style="display:flex;gap:1rem;align-items:flex-start;
                            padding:0.85rem 1rem;margin:0.4rem 0;
                            background:rgba(168,85,247,0.04);
                            border:1px solid rgba(168,85,247,0.12);
                            border-radius:10px;">
                    <span style="font-size:1.1rem;line-height:1.4;">{dot}</span>
                    <div>
                        <div style="font-size:1.1rem;font-weight:700;color:#c4b5fd;
                                    text-transform:uppercase;letter-spacing:0.04em;
                                    margin-bottom:0.3rem;">{title}</div>
                        <div style="font-size:1rem;color:#94a3b8;line-height:1.55;">{body}</div>
                    </div>
                </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Compliance checklist
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#a855f7;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">✅ Compliance & Directive Alignment</div>
            """, unsafe_allow_html=True)

            compliance_items = [
                ("BOD 22-01", "CISA Binding Operational Directive — remediate all KEV items within defined windows", True),
                ("DFARS 252.204-7012", "Report cyber incidents on covered defense systems within 72 hours", True),
                ("CMMC Level 2", "Implement NIST SP 800-171 controls across contractor information systems", False),
                ("NIST RMF", "Continuous monitoring and authorization to operate (ATO) maintenance", True),
            ]

            for directive, description, aligned in compliance_items:
                status_color = "#34d399" if aligned else "#f97316"
                status_label = "Addressed by Platform" if aligned else "Requires Manual Process"
                status_icon  = "✓" if aligned else "⚠"
                st.markdown(f"""
                <div style="display:flex;justify-content:space-between;align-items:center;
                            padding:0.7rem 1rem;margin:0.3rem 0;
                            border-bottom:1px solid #1e293b;">
                    <div>
                        <span style="font-family:'Space Mono',monospace;font-size:1rem;
                                     font-weight:700;color:#a855f7;">{directive}</span>
                        <span style="font-size:0.9rem;color:#64748b;margin-left:0.8rem;">{description}</span>
                    </div>
                    <span style="background:{status_color}18;color:{status_color};
                                 border:1px solid {status_color}44;border-radius:6px;
                                 padding:0.2rem 0.7rem;font-size:1rem;font-weight:700;
                                 white-space:nowrap;">{status_icon} {status_label}</span>
                </div>""", unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # ROLE 2 — ANALYST DRILL-DOWN
        # ══════════════════════════════════════════════════════════════════════
        elif "Analyst" in role:

            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.3rem;font-weight:700;
                        color:#38bdf8;margin-bottom:0.2rem;">🔐 Analyst Drill-Down</div>
            <div style="font-size:0.82rem;color:#64748b;margin-bottom:1.2rem;">
                Technical depth view for SOC analysts and threat intelligence teams.
                Focused on triage logic, exploitation mechanics, and hunt/detect priorities.
            </div>
            """, unsafe_allow_html=True)

            # Triage priority framework
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#38bdf8;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">⚡ Triage Priority Framework</div>
            """, unsafe_allow_html=True)

            triage_levels = [
                ("P1 — IMMEDIATE", "#ef4444", "Act within 24 hours",
                 ["In CISA KEV catalog", "CVSS ≥ 9.0", "Ransomware-linked", "Network-accessible attack vector"],
                 "Patch or implement compensating controls within 24 hours. Notify security leadership. "
                 "Check for indicators of compromise before patching — assume breach on internet-exposed systems."),
                ("P2 — URGENT", "#f97316", "Act within 72 hours",
                 ["In CISA KEV catalog", "CVSS 7.0–8.9", "Requires local access or user interaction"],
                 "Schedule emergency change window. Prioritize systems processing CUI or connected to classified networks. "
                 "Deploy detection rules for exploitation attempts in SIEM."),
                ("P3 — ELEVATED", "#eab308", "Act within 14 days",
                 ["High CVSS but not yet in KEV", "Proof-of-concept exploit public", "Adjacent attack vector"],
                 "Include in next patch cycle. Monitor threat feeds for KEV addition. "
                 "Apply network segmentation as interim control where patching is delayed."),
                ("P4 — ROUTINE", "#34d399", "Act within 30 days",
                 ["Medium/Low CVSS", "No known exploitation", "Requires significant prerequisites"],
                 "Handle through standard patch management workflow. Document risk acceptance if deferral is needed. "
                 "Reassess if threat intelligence changes."),
            ]

            for level, color, timing, criteria, action in triage_levels:
                with st.expander(f"{level}  ·  {timing}", expanded=(level == "P1 — IMMEDIATE")):
                    crit_html = "".join(
                        f'<div style="display:flex;gap:0.5rem;align-items:center;padding:0.3rem 0;">'
                        f'<span style="color:{color};font-weight:700;">▸</span>'
                        f'<span style="font-size:1rem;color:#cbd5e1;">{c}</span></div>'
                        for c in criteria
                    )
                    st.markdown(f"""
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;padding:0.4rem 0;">
                        <div>
                            <div style="font-size:1rem;color:#64748b;text-transform:uppercase;
                                        letter-spacing:0.06em;margin-bottom:0.4rem;">Trigger Criteria</div>
                            {crit_html}
                        </div>
                        <div>
                            <div style="font-size:1rem;color:#64748b;text-transform:uppercase;
                                        letter-spacing:0.06em;margin-bottom:0.4rem;">Analyst Action</div>
                            <div style="font-size:1rem;color:#94a3b8;line-height:1.55;">{action}</div>
                        </div>
                    </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Threat actor targeting matrix
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#38bdf8;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">🎯 Threat Actor Targeting Matrix</div>
            """, unsafe_allow_html=True)

            actors = [
                ("APT40 (China)", "Microsoft Exchange, Outlook", "Network / Adjacent", "High", "Defense contractors, maritime, aviation"),
                ("APT29 (Russia)", "Microsoft AD, OAuth, MFA bypass", "Network", "Critical", "Government, defense industrial base"),
                ("Lazarus Group (DPRK)", "Cisco VPN, remote access", "Network", "High", "Aerospace, defense, crypto"),
                ("FIN7 / Carbanak", "Microsoft Office macros, RCE", "User Interaction", "High", "Financial, defense supply chain"),
                ("LockBit (RaaS)", "Cisco ASA, Exchange, Citrix", "Network", "Critical", "Ransomware-as-a-service, broad targeting"),
            ]

            header_cols = st.columns([2, 2.5, 1.5, 1, 2.5])
            for col, label in zip(header_cols, ["Threat Actor", "Primary CVE Targets", "Vector", "Risk", "Sector Focus"]):
                col.markdown(f"<div style='font-size:0.9rem;color:#475569;text-transform:uppercase;"
                             f"letter-spacing:0.07em;font-weight:700;padding:0.3rem 0;'>{label}</div>",
                             unsafe_allow_html=True)

            risk_colors = {"Critical": "#ef4444", "High": "#f97316"}
            for actor, targets, vector, risk, sectors in actors:
                c1, c2, c3, c4, c5 = st.columns([2, 2.5, 1.5, 1, 2.5])
                rc = risk_colors.get(risk, "#94a3b8")
                c1.markdown(f"<div style='font-size:1rem;color:#e2e8f0;padding:0.5rem 0;font-weight:600;'>{actor}</div>", unsafe_allow_html=True)
                c2.markdown(f"<div style='font-size:1rem;color:#94a3b8;padding:0.5rem 0;'>{targets}</div>", unsafe_allow_html=True)
                c3.markdown(f"<div style='font-size:1rem;color:#64748b;padding:0.5rem 0;'>{vector}</div>", unsafe_allow_html=True)
                c4.markdown(f"<div style='background:{rc}18;color:{rc};border:1px solid {rc}44;"
                            f"border-radius:5px;padding:0.2rem 0.5rem;font-size:1rem;"
                            f"font-weight:700;text-align:center;margin-top:0.4rem;'>{risk}</div>", unsafe_allow_html=True)
                c5.markdown(f"<div style='font-size:1rem;color:#64748b;padding:0.5rem 0;'>{sectors}</div>", unsafe_allow_html=True)
                st.markdown("<div style='border-bottom:1px solid #1e293b;'></div>", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Detection & hunt guidance
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#38bdf8;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">🔍 Detection & Hunt Guidance</div>
            """, unsafe_allow_html=True)

            hunt_items = [
                ("Microsoft AD / Exchange",
                 ["Hunt for Kerberoasting (Event ID 4769 with RC4 encryption)", "Monitor for LSASS memory access (Sysmon Event 10)", "Alert on unusual OAuth token issuance outside business hours", "Check for Exchange ProxyLogon/ProxyShell web shell artifacts in IIS logs"]),
                ("Cisco IOS / ASA",
                 ["Audit devices for unexpected config changes (no service password-encryption)", "Hunt for SNMP community string brute force in netflow", "Monitor for IOS XE web UI access from non-admin subnets", "Review VPN auth logs for credential stuffing patterns"]),
                ("Google Workspace",
                 ["Review Workspace Admin audit logs for delegated credential abuse", "Alert on Drive mass-download events outside normal hours", "Monitor for OAuth app approvals with broad scope (drive.*, admin.*)", "Check for forwarding rules silently added to executive mailboxes"]),
            ]

            for vendor, hunts in hunt_items:
                with st.expander(f"🔎 {vendor}", expanded=False):
                    for hunt in hunts:
                        st.markdown(f"""
                        <div style="display:flex;gap:0.75rem;align-items:flex-start;
                                    padding:0.5rem 0;border-bottom:1px solid #1e293b;">
                            <span style="color:#38bdf8;font-weight:700;font-size:1rem;
                                         margin-top:1px;">›</span>
                            <span style="font-size:1rem;color:#94a3b8;line-height:1.5;">{hunt}</span>
                        </div>""", unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════════════
        # ROLE 3 — OPERATIONS VIEW
        # ══════════════════════════════════════════════════════════════════════
        elif "Operations" in role:

            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.3rem;font-weight:700;
                        color:#34d399;margin-bottom:0.2rem;">💼 Operations View</div>
            <div style="font-size:0.82rem;color:#64748b;margin-bottom:1.2rem;">
                Practical remediation guidance for IT and network infrastructure teams.
                Focused on patch checklists, configuration hardening, and escalation workflows.
            </div>
            """, unsafe_allow_html=True)

            # Patch checklist by vendor
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#34d399;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">🛠️ Patch & Remediation Checklist by Vendor</div>
            """, unsafe_allow_html=True)

            vendor_checklists = {
                "🪟 Microsoft": {
                    "color": "#38bdf8",
                    "steps": [
                        ("Inventory", "Run WSUS/Intune compliance report — identify unpatched Windows Server and Exchange systems"),
                        ("Prioritize", "Filter by KEV status first, then CVSS ≥ 9.0, then network-accessible attack vectors"),
                        ("Test", "Deploy patches to non-production environment; validate no service disruption for AD and Exchange"),
                        ("Deploy", "Push via WSUS/SCCM/Intune with reboot scheduling during approved maintenance windows"),
                        ("Verify", "Confirm patch installation via compliance dashboard; re-scan with Nessus/Qualys"),
                        ("Document", "Log patch deployment in ITSM; record any risk acceptance if deferred per POAM"),
                    ],
                },
                "🔵 Cisco": {
                    "color": "#0ea5e9",
                    "steps": [
                        ("Inventory", "Pull device list from DNA Center or network CMDB; include IOS XE, ASA, and VPN concentrators"),
                        ("Check", "Cross-reference firmware versions against Cisco PSIRT advisories for KEV-listed CVEs"),
                        ("Prioritize", "Focus on internet-facing ASA/FTD and IOS XE web UI enabled devices first"),
                        ("Upgrade", "Follow Cisco TAC upgrade path; use redundant hardware where available for zero-downtime patching"),
                        ("Harden", "Disable IOS XE HTTP server if not required (no ip http server); restrict management access via ACL"),
                        ("Validate", "Verify connectivity post-upgrade; test VPN tunnels and routing protocols before sign-off"),
                    ],
                },
                "🟡 Google Workspace": {
                    "color": "#eab308",
                    "steps": [
                        ("Audit", "Review Google Admin Console for third-party OAuth apps with broad permissions"),
                        ("Revoke", "Remove unauthorized OAuth app access; enforce admin approval for new app installs"),
                        ("MFA", "Enforce phishing-resistant MFA (hardware keys or Google Passkeys) for all admin accounts"),
                        ("Alerts", "Configure Workspace Admin alerts for suspicious login events and bulk Drive access"),
                        ("Review", "Audit forwarding rules and delegates on executive/sensitive mailboxes quarterly"),
                        ("Update", "Ensure Chrome Browser Enterprise is current — Google Chrome CVEs in KEV require prompt update"),
                    ],
                },
            }

            for vendor, data in vendor_checklists.items():
                with st.expander(vendor, expanded=False):
                    for i, (step_label, step_desc) in enumerate(data["steps"], 1):
                        st.markdown(f"""
                        <div style="display:flex;gap:1rem;align-items:flex-start;
                                    padding:0.65rem 0;border-bottom:1px solid #1e293b;">
                            <span style="background:{data['color']}18;color:{data['color']};
                                         border:1px solid {data['color']}44;border-radius:5px;
                                         padding:0.15rem 0.55rem;font-size:1rem;font-weight:700;
                                         white-space:nowrap;font-family:'Space Mono',monospace;">
                                {i}. {step_label}
                            </span>
                            <span style="font-size:1rem;color:#94a3b8;line-height:1.5;">{step_desc}</span>
                        </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Escalation workflow
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#34d399;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">📣 Escalation Workflow</div>
            """, unsafe_allow_html=True)

            escalation_steps = [
                ("#ef4444", "Identify", "CVE discovered in KEV catalog matching your vendor/product inventory"),
                ("#f97316", "Assess",   "Confirm exploitability in your environment (attack vector, auth required, version match)"),
                ("#eab308", "Notify",   "Alert SOC lead and CISO within 4 hours for P1/P2; document in ITSM ticket"),
                ("#38bdf8", "Remediate","Apply patch or compensating control per vendor checklist above"),
                ("#a855f7", "Verify",   "Re-scan system; confirm patch in CMDB; close ITSM ticket with evidence"),
                ("#34d399", "Report",   "If CUI systems affected: submit DFARS 252.204-7012 incident report within 72 hours"),
            ]

            cols = st.columns(len(escalation_steps))
            for col, (color, label, desc) in zip(cols, escalation_steps):
                col.markdown(f"""
                <div style="background:{color}10;border:1px solid {color}33;
                            border-top:3px solid {color};border-radius:8px;
                            padding:0.85rem 0.75rem;text-align:center;height:140px;">
                    <div style="font-family:'Space Mono',monospace;font-size:1rem;
                                font-weight:700;color:{color};margin-bottom:0.5rem;">{label}</div>
                    <div style="font-size:1rem;color:#64748b;line-height:1.4;">{desc}</div>
                </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Quick reference SLA table
            st.markdown("""
            <div style="font-family:'Space Mono',monospace;font-size:1.1rem;font-weight:700;
                        color:#34d399;text-transform:uppercase;letter-spacing:0.06em;
                        margin-bottom:0.6rem;">⏱️ Patch SLA Quick Reference</div>
            """, unsafe_allow_html=True)

            sla_data = [
                ("Critical + KEV + Ransomware",  "24 hours",  "#ef4444", "Critical", "Emergency change; escalate immediately"),
                ("Critical + KEV",               "72 hours",  "#f97316", "Critical", "Emergency change window required"),
                ("High + KEV",                   "7 days",    "#eab308", "High",     "Priority patch cycle"),
                ("Critical, not in KEV",         "14 days",   "#38bdf8", "Medium",   "Next available maintenance window"),
                ("High, not in KEV",             "30 days",   "#64748b", "Low",      "Standard patch cycle"),
                ("Medium / Low",                 "90 days",   "#475569", "Routine",  "Routine patch cycle or risk accept"),
            ]

            hdr = st.columns([3, 1.5, 1.5, 3])
            for col, lbl in zip(hdr, ["Condition", "SLA", "Priority", "Action"]):
                col.markdown(f"<div style='font-size:.9rem;color:#475569;text-transform:uppercase;"
                            f"letter-spacing:0.07em;font-weight:700;padding:0.3rem 0;'>{lbl}</div>",
                            unsafe_allow_html=True)

            for condition, sla, color, priority, action in sla_data:
                c1, c2, c3, c4 = st.columns([3, 1.5, 1.5, 3])
                c1.markdown(f"<div style='font-size:1rem;color:#e2e8f0;padding:0.45rem 0;'>{condition}</div>", unsafe_allow_html=True)
                c2.markdown(f"<div style='font-family:Space Mono,monospace;font-size:1rem;color:{color};"
                            f"font-weight:700;padding:0.45rem 0;'>{sla}</div>", unsafe_allow_html=True)
                c3.markdown(f"<div style='background:{color}18;color:{color};border:1px solid {color}44;"
                            f"border-radius:5px;padding:0.2rem 0.5rem;font-size:1rem;"
                            f"font-weight:700;text-align:center;margin-top:0.3rem;'>{priority}</div>", unsafe_allow_html=True)
                c4.markdown(f"<div style='font-size:1rem;color:#64748b;padding:0.45rem 0;'>{action}</div>", unsafe_allow_html=True)
                st.markdown("<div style='border-bottom:1px solid #1e293b;'></div>", unsafe_allow_html=True)
