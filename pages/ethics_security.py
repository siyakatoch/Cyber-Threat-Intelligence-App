import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json

def render():
    st.markdown('<div class="section-header">💡 Ethics & Security Practices</div>', unsafe_allow_html=True)

    tab_ethics, tab_security, = st.tabs([
        "⚖️ Ethics",
        "🔐 Security Practices"
    ])

    # ─────────────────────────────────────────────────────────────
    # TAB 1 — ETHICS
    # ─────────────────────────────────────────────────────────────
    with tab_ethics:
        st.markdown("""
        <div class="info-box">
        This platform was developed strictly using <strong>publicly available, unclassified data</strong>
        sourced from official government agencies and reputable cybersecurity research organizations.
        No sensitive, classified, proprietary, or controlled unclassified information (CUI) was accessed,
        reproduced, or referenced at any point during the development of this project. All threat
        intelligence, vulnerability data, and incident reporting used on this platform has been
        officially released for public consumption.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown("""
            <div class="info-box" style="min-height:200px">
                <div style="font-family:'Space Mono',monospace;font-size:0.85rem;
                            color:#38bdf8;margin-bottom:0.6rem;">✅ Use of Public Data Only</div>
                All data on this platform traces to publicly accessible government sources —
                CISA advisories, FBI alerts, NSA unclassified guidance, MITRE ATT&CK group
                profiles, DNI annual threat assessments, and DCSA public threat reporting.
                No private, proprietary, or restricted data feeds were used.
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown("""
            <div class="info-box" style="min-height:200px">
                <div style="font-family:'Space Mono',monospace;font-size:0.85rem;
                            color:#38bdf8;margin-bottom:0.6rem;">🚫 No Sensitive or Classified Information</div>
                Zero classified, restricted, or controlled unclassified information (CUI) is
                present anywhere on this platform. All threat actor TTPs, CVEs, and incident
                details are sourced exclusively from publicly released documents. All
                intelligence is TLP:CLEAR — publicly releasable with no restrictions.
            </div>
            """, unsafe_allow_html=True)

        with c3:
            st.markdown("""
            <div class="info-box" style="min-height:200px">
                <div style="font-family:'Space Mono',monospace;font-size:0.85rem;
                            color:#38bdf8;margin-bottom:0.6rem;">🔒 Responsible Handling of Data</div>
                No personally identifiable information (PII) is collected or displayed.
                Active IOC lists, unpatched exploitation steps, and unpublished attack tooling
                were intentionally omitted. All research was conducted passively — no network
                scanning, probing, or unauthorized access was performed at any point.
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="sub-header">📋 Redactions Applied</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="threat-box">
            The following categories of information were intentionally omitted from this platform
            regardless of public availability:<br><br>
            <strong>🔴 Active IOC lists</strong> — IP addresses, domains, and hashes that could be misused for offensive purposes<br>
            <strong>🔴 Exploitation step-by-step details</strong> — specific technical procedures for exploiting unpatched vulnerabilities<br>
            <strong>🔴 Unpublished attack tooling</strong> — proof-of-concept code and pre-disclosure vulnerability research<br>
            <strong>🔴 Active investigation details</strong> — law enforcement sensitive information or grand jury material<br><br>
            Only information already in the public domain through <strong>official government disclosure channels</strong> is presented.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # ── Sources (expandable) ──────────────────────────────────
        with st.expander("📚 Primary Data Sources", expanded=False):
            sources = [
                (
                    "CISA Known Exploited Vulnerabilities (KEV) Catalog",
                    "The authoritative catalog of CVEs actively exploited in the wild, maintained by CISA. "
                    "Used as the primary source for all vendor vulnerability data on this platform. "
                    "Federal agencies and contractors are required to remediate KEV entries under BOD 22-01.",
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                ),
                (
                    "CISA Ransomware Vulnerability Warning Pilot (RVWP)",
                    "CISA's proactive program that notifies organizations of ransomware-exploitable "
                    "vulnerabilities in their internet-facing systems. Used to validate ransomware "
                    "group exploitation patterns against defense contractor environments.",
                    "https://www.cisa.gov/stopransomware/Ransomware-Vulnerability-Warning-Pilot",
                ),
                (
                    "FBI Flash Reports Index — IC3",
                    "FBI Cyber Division public threat alerts and Internet Crime Complaint Center "
                    "flash reports released for general private sector awareness. Used for ransomware "
                    "group activity and DIB targeting context throughout this platform.",
                    "https://www.ic3.gov/Media/News/2024",
                ),
                (
                    "CISA StopRansomware Advisories",
                    "Joint CISA/FBI/NSA advisories on active ransomware groups including LockBit, "
                    "Akira, RansomHub, Black Basta, and Cl0p. Primary source for all CISA advisory "
                    "numbers, ransomware TTPs, and CMMC control gap mappings in the advisory tracker.",
                    "https://www.cisa.gov/stopransomware",
                ),
            ]

            for label, desc, url in sources:
                st.markdown(f"""
                <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                            border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                            padding:0.85rem 1.1rem;margin:0.5rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.8rem;
                                color:#38bdf8;margin-bottom:0.3rem;">📄 {label}</div>
                    <div style="font-size:0.84rem;color:#94a3b8;margin-bottom:0.4rem;">{desc}</div>
                    <a href="{url}" target="_blank"
                       style="font-size:0.76rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>
                """, unsafe_allow_html=True)

    # ─────────────────────────────────────────────────────────────
    # TAB 2 — SECURITY PRACTICES
    # ─────────────────────────────────────────────────────────────
    with tab_security:
        st.markdown("""
        <div class="info-box">
        This platform was designed with security-aware development principles to ensure that no sensitive data is exposed,
        no unsafe functionality is introduced, and all threat intelligence is handled in a controlled and defensive manner.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        points = [
            ("<strong>No Hardcoded Secrets</strong>",
             "The application does not contain API keys, credentials, tokens, or any sensitive authentication data in the codebase."),
            ("<strong>Read-Only Data Usage</strong>",
             "All datasets are used strictly for visualization and analysis. No modification or write operations are performed."),
            ("<strong>Minimal Attack Surface</strong>",
             "The app does not accept free-form user input or execute dynamic commands, reducing risk of injection or misuse."),
            ("<strong>Controlled Data Exposure</strong>",
             "Only relevant fields such as CVE ID and severity are displayed. Sensitive operational context is intentionally excluded."),
            ("<strong>Safe Use of Vulnerability Intelligence</strong>",
             "No exploit code, payloads, or weaponization details are included anywhere on the platform."),
            ("<strong>Rate Limit and Source Respect</strong>",
             "Data is sourced from public repositories without scraping or excessive automated requests."),
        ]

        for title, desc in points:
            st.markdown(f"""
            <div class="info-box" style="display:flex;align-items:flex-start;gap:0.75rem;margin-bottom:0.5rem;">
                <span style="color:#38bdf8;font-size:1.1rem;line-height:1.6;">🔹</span>
                <div>
                    <div style="font-family:'Space Mono',monospace;font-size:0.82rem;color:#38bdf8;margin-bottom:0.2rem;">{title}</div>
                    <div style="font-size:0.88rem;color:#94a3b8;">{desc}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="sub-header">🛡️ CMMC & Compliance Alignment</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        While this platform is a research and intelligence tool — not a compliance system — its design philosophy
        is consistent with several Cybersecurity Maturity Model Certification (CMMC) Level 2 practices:<br><br>
        <strong>AC.2.006</strong> — Use of least privilege for data access and display<br>
        <strong>AU.2.041</strong> — Audit logging of user-facing sessions is not performed, avoiding unnecessary data collection<br>
        <strong>CM.2.061</strong> — Baseline configurations are maintained; no dynamic execution or runtime code injection<br>
        <strong>IA.3.083</strong> — No credential storage or authentication bypass vectors are present<br>
        <strong>SI.1.210</strong> — All displayed vulnerability data references only patched or publicly disclosed CVEs
        </div>
        """, unsafe_allow_html=True)