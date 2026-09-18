import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def render():
    st.markdown('<div class="section-header">📡 CTI Data Sources</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
        Identification and justification of primary CTI data sources used throughout this platform.
        Each source is evaluated against the Diamond Model of Intrusion Analysis and assessed for
        industry relevance, data volume, collection methodology, and organizational adoption.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs(["🏛️ CISA — Known Exploited Vulnerabilities", "📋 NIST — National Vulnerability Database", "❔ Collection Strategies and Data Summary", "📊 Metrics & Validation"])

    # ════════════════════════════════════════════════════════════════════
    # TAB 1 — CISA KEV
    # ════════════════════════════════════════════════════════════════════
    with tab1:

        st.markdown("""
        <div style="background:rgba(14,165,233,0.06);border:1px solid rgba(56,189,248,0.2);
                    border-left:4px solid #38bdf8;border-radius:0 12px 12px 0;
                    padding:1.2rem 1.5rem;margin-bottom:1.5rem;">
            <div style="font-family:'Space Mono',monospace;font-size:1rem;font-weight:700;
                         color:#38bdf8;margin-bottom:0.3rem;">
                CISA Known Exploited Vulnerabilities (KEV) Catalog
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6;">
                Cybersecurity & Infrastructure Security Agency &nbsp;·&nbsp;
                U.S. Department of Homeland Security &nbsp;·&nbsp;
                <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                   target="_blank" style="color:#0ea5e9;text-decoration:none;">
                   cisa.gov/known-exploited-vulnerabilities-catalog
                </a>
            </div>
        </div>
        """, unsafe_allow_html=True)

        k1, k2, k3, k4 = st.columns(4)
        kpi_data = [
            (k1, "1,500+", "CVEs in Catalog", "Continuously updated"),
            (k2, "2021", "Catalog Established", "BOD 22-01 mandate"),
            (k3, "~50", "New Entries / Month", "Avg addition rate"),
            (k4, "Free", "Access Cost", "Publicly available"),
        ]
        for col, val, label, delta in kpi_data:
            with col:
                st.markdown(f"""
                <div style="background:rgba(14,165,233,0.06);border:1px solid rgba(56,189,248,0.18);
                            border-radius:12px;padding:1rem 1.2rem;text-align:center;">
                    <div style="font-family:'Space Mono',monospace;font-size:1.8rem;
                                 font-weight:700;color:#38bdf8;line-height:1.1;">{val}</div>
                    <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;
                                 letter-spacing:0.07em;margin-top:0.3rem;">{label}</div>
                    <div style="font-size:0.7rem;color:#f97316;margin-top:0.2rem;">{delta}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        c1, c2 = st.columns(2)

        with c1:
            st.markdown('<div class="sub-header">💡 Value to the Defense Sector</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The CISA KEV catalog provides <strong>operationally prioritized vulnerability intelligence</strong>
            specifically curated for organizations operating under federal and defense mandates.
            Unlike the full NVD catalog of 200,000+ CVEs, the KEV catalog filters only those
            vulnerabilities with <strong>confirmed active exploitation in the wild</strong> — making it
            the highest-signal, lowest-noise source available for patch prioritization decisions.
            <br><br>
            For cleared defense contractors (CDCs) and Defense Industrial Base (DIB) organizations,
            the KEV catalog directly maps to mandatory patching obligations under
            <strong>Binding Operational Directive 22-01</strong>, which requires all Federal Civilian
            Executive Branch (FCEB) agencies to remediate KEV entries within defined windows
            (typically 2–3 weeks for critical entries). While BOD 22-01 is technically mandatory only
            for FCEB agencies, DoD and defense contractors are strongly expected to align with it
            under CMMC 2.0 and NIST SP 800-171 compliance frameworks.
            <br><br>
            The catalog supports all four nodes of the <strong>Diamond Model</strong>:
            it informs <em>Capability</em> analysis (which vulnerabilities adversaries are actively
            weaponizing), <em>Infrastructure</em> analysis (which products and vendors are being
            exploited), and <em>Victim</em> analysis (which sectors and asset types are most exposed).
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="sub-header">🏛️ Who Generates This Data?</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The KEV catalog is produced and maintained by <strong>CISA</strong> (Cybersecurity &
            Infrastructure Security Agency), a component of the U.S. Department of Homeland Security.
            CISA was established under the Cybersecurity and Infrastructure Security Agency Act of 2018.
            <br><br>
            Entries are added based on evidence of <strong>active exploitation confirmed through</strong>:
            <ul style="margin-top:0.5rem;padding-left:1.2rem;color:#cbd5e1;">
                <li>CISA's own threat hunting and incident response operations</li>
                <li>Reporting from federal agencies, CISAs and ISACs</li>
                <li>Vetted commercial threat intelligence partner submissions</li>
                <li>Public reporting from major security vendors (Microsoft, Google, Mandiant, CrowdStrike)</li>
                <li>FBI and NSA joint advisory intelligence</li>
            </ul>
            <br>
            Each entry is reviewed by CISA analysts before inclusion. The catalog is governed by
            <strong>BOD 22-01</strong> (Nov 2021) and supplemented by Emergency Directives
            (ED 25-02, ED 25-03, ED 26-03) for the highest-urgency vulnerabilities.
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown('<div class="sub-header">📊 Data Volume & Coverage</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            As of April 2026, the KEV catalog contains <strong>over 1,500 CVE entries</strong>
            spanning vulnerabilities dating back to 2002. Key coverage statistics:
            <ul style="margin-top:0.5rem;padding-left:1.2rem;color:#cbd5e1;">
                <li><strong>~50 new entries added per month</strong> on average</li>
                <li>Covers <strong>200+ vendors</strong> including Microsoft, Cisco, Fortinet, Ivanti, Google, Apple, and VMware</li>
                <li>Includes severity classification (Critical/High), ransomware use flag, CWE weakness type, governing directive, and remediation due date</li>
                <li>Available as a <strong>JSON/CSV feed</strong> for automated ingestion into SIEM, SOAR, and vulnerability management platforms</li>
                <li>Our curated dataset focuses on <strong>100 defense/government-relevant entries</strong> prioritized by BOD 22-01, active exploitation, and DoD/FCEB prevalence</li>
            </ul>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="sub-header">🎯 Why We Selected This Source</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            CISA KEV was selected as our primary vulnerability intelligence source for four reasons:
            <br><br>
            <strong>1. Authoritative & Mandatory:</strong> It is the only government-mandated
            vulnerability catalog in the US federal ecosystem. For defense contractors, alignment
            with KEV is not optional — it is an implicit requirement under CMMC 2.0 and DFARS.
            <br><br>
            <strong>2. Diamond Model Alignment:</strong> The KEV catalog directly supports
            Capability node analysis — each entry represents a confirmed adversary capability
            actively being weaponized. Entries like T1566 (phishing) and T1078 (valid accounts)
            map directly to TTPs used by Volt Typhoon, APT29, and Lazarus Group documented in
            our diamond models.
            <br><br>
            <strong>3. Noise Reduction:</strong> Out of 200,000+ known CVEs, KEV's ~1,500 entries
            represent confirmed exploitation — a ~0.75% signal rate that eliminates alert fatigue
            and focuses analyst attention on real threats.
            <br><br>
            <strong>4. Free & Machine-Readable:</strong> The full catalog is publicly available
            via JSON API, enabling direct integration into our dashboard pipeline.
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="sub-header">🏢 Industry Adoption</div>', unsafe_allow_html=True)
        adopters = [
            ("DoD / FCEB Agencies", "Mandatory compliance under BOD 22-01. All 102 FCEB agencies are legally required to remediate KEV entries within directive timelines."),
            ("Defense Contractors (CDCs / DIB)", "Used for CMMC 2.0 compliance gap analysis, DFARS 252.204-7012 reporting, and aligning patch cycles with federal expectations."),
            ("CrowdStrike / Palo Alto / Tenable", "Commercial vulnerability scanners and EDR platforms ingest KEV as a priority feed to auto-flag confirmed exploitation in customer environments."),
            ("SIEM / SOAR Platforms (Splunk, Microsoft Sentinel)", "KEV entries are used as enrichment data to automatically elevate alert severity for CVEs confirmed in active campaigns."),
            ("Healthcare & Critical Infrastructure ISACs", "H-ISAC, E-ISAC, and WaterISAC distribute KEV advisories to sector members as the baseline for cross-sector patching coordination."),
            ("Academic & Think Tank Researchers", "RAND, MITRE, and Carnegie Endowment researchers use KEV as an empirical dataset for measuring patch compliance, exploitation timelines, and policy effectiveness."),
        ]
        for org, reason in adopters:
            st.markdown(f"""
            <div style="display:flex;gap:1rem;padding:0.6rem 0;border-bottom:1px solid #1e293b;
                        align-items:flex-start;">
                <span style="font-size:0.78rem;font-weight:700;color:#38bdf8;min-width:220px;
                             padding-top:0.05rem;">{org}</span>
                <span style="font-size:0.82rem;color:#94a3b8;line-height:1.5;">{reason}</span>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown('<div class="sub-header">🔄 Collection Strategy & Integration</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        <strong>Source:</strong> CISA KEV JSON feed at
        <code style="background:rgba(56,189,248,0.1);padding:1px 6px;border-radius:4px;color:#7dd3fc;">
        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        </code>
        <br><br>
        <strong>Our pipeline:</strong> The full catalog was filtered to 100 defense/government-relevant
        entries using three prioritization criteria: (1) governing directive is BOD 22-01 or an
        Emergency Directive, (2) active exploitation confirmed in DoD/FCEB environments, and
        (3) vendor products prevalent in defense sector IT stacks (Windows, Cisco IOS, Fortinet FortiOS,
        Ivanti Connect Secure, VMware ESXi). CVSS scores were merged from NIST NVD to produce
        the <code style="background:rgba(56,189,248,0.1);padding:1px 6px;border-radius:4px;color:#7dd3fc;">Data_with_Scores.json</code> enrichment layer.
        <br><br>
        <strong>Minimum data expectations:</strong> Each entry must include CVE ID, vendor, product,
        vulnerability name, severity (Critical/High), date added, due date, ransomware use flag,
        CWE classification, and governing directive. Entries missing severity or directive are excluded.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📚 References", expanded=False):
            for label, url in [
                ("CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("BOD 22-01 — Reducing the Significant Risk of Known Exploited Vulnerabilities", "https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities"),
                ("CISA — China Cyber Threat Overview and Advisories", "https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors/china"),
                ("CISA Advisory AA24-038A — Volt Typhoon", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"),
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

    # ════════════════════════════════════════════════════════════════════
    # TAB 2 — NIST NVD
    # ════════════════════════════════════════════════════════════════════
    with tab2:

        st.markdown("""
        <div style="background:rgba(52,211,153,0.06);border:1px solid rgba(52,211,153,0.2);
                    border-left:4px solid #34d399;border-radius:0 12px 12px 0;
                    padding:1.2rem 1.5rem;margin-bottom:1.5rem;">
            <div style="font-family:'Space Mono',monospace;font-size:1rem;font-weight:700;
                         color:#34d399;margin-bottom:0.3rem;">
                NIST National Vulnerability Database (NVD) — CVSS Scoring
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6;">
                National Institute of Standards and Technology &nbsp;·&nbsp;
                U.S. Department of Commerce &nbsp;·&nbsp;
                <a href="https://nvd.nist.gov" target="_blank"
                   style="color:#34d399;text-decoration:none;">nvd.nist.gov</a>
            </div>
        </div>
        """, unsafe_allow_html=True)

        k1, k2, k3, k4 = st.columns(4)
        kpi_data2 = [
            (k1, "230,000+", "CVEs in NVD", "Full catalog coverage"),
            (k2, "1999", "Database Founded", "25+ years of data"),
            (k3, "CVSS v3.1", "Scoring Standard", "Base / Impact / Exploit"),
            (k4, "Free API", "Access Method", "REST API + JSON feeds"),
        ]
        for col, val, label, delta in kpi_data2:
            with col:
                st.markdown(f"""
                <div style="background:rgba(52,211,153,0.06);border:1px solid rgba(52,211,153,0.2);
                            border-radius:12px;padding:1rem 1.2rem;text-align:center;">
                    <div style="font-family:'Space Mono',monospace;font-size:1.8rem;
                                 font-weight:700;color:#34d399;line-height:1.1;">{val}</div>
                    <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;
                                 letter-spacing:0.07em;margin-top:0.3rem;">{label}</div>
                    <div style="font-size:0.7rem;color:#f97316;margin-top:0.2rem;">{delta}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        c1, c2 = st.columns(2)

        with c1:
            st.markdown('<div class="sub-header">💡 Value to the Defense Sector</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The NIST NVD provides the <strong>quantitative scoring backbone</strong> for vulnerability
            risk prioritization across the entire cybersecurity industry. While CISA KEV tells us
            <em>which</em> vulnerabilities are being actively exploited, NVD tells us
            <em>how severe</em> each vulnerability is through standardized
            <strong>CVSS v3.1 scoring</strong> — breaking severity into three dimensions:
            Base Score, Impact Score, and Exploitability Score.
            <br><br>
            For defense organizations, NVD's CVSS scores serve as the <strong>risk quantification
            layer</strong> that feeds into patch prioritization matrices, risk registers, and
            POAM (Plan of Action & Milestones) documentation required under FISMA, NIST SP 800-37
            (Risk Management Framework), and CMMC 2.0. Without CVSS scores, organizations cannot
            objectively compare the relative risk of two vulnerabilities or meet the RMF's
            quantitative risk assessment requirements.
            <br><br>
            In our dashboard, NVD CVSS data is used to enrich CISA KEV entries with Base Score,
            Impact Score, and Exploitability Score — enabling analysts to filter and sort
            vulnerabilities by objective severity metrics rather than categorical labels alone.
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="sub-header">🏛️ Who Generates This Data?</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The NVD is operated by the <strong>National Institute of Standards and Technology (NIST)</strong>,
            a non-regulatory agency of the U.S. Department of Commerce. NIST has maintained the NVD
            since 1999 as the U.S. government's official repository of standards-based vulnerability
            management data.
            <br><br>
            NVD analysts enrich CVE records published by <strong>MITRE's CVE Program</strong> with:
            <ul style="margin-top:0.5rem;padding-left:1.2rem;color:#cbd5e1;">
                <li>CVSS v2.0, v3.0, v3.1, and v4.0 base scores</li>
                <li>Common Platform Enumeration (CPE) affected product mappings</li>
                <li>Common Weakness Enumeration (CWE) classification</li>
                <li>References to vendor advisories, PoC exploits, and patch notes</li>
                <li>Vulnerability status (Analyzed, Awaiting Analysis, Modified, Rejected)</li>
            </ul>
            <br>
            NVD is the <strong>authoritative US government source</strong> for CVSS scores —
            scores from NVD are considered the official reference by NIST SP 800-53, NIST SP 800-171,
            and the DoD RMF.
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown('<div class="sub-header">📊 Data Volume & Coverage</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The NVD is the largest standardized vulnerability database in the world:
            <ul style="margin-top:0.5rem;padding-left:1.2rem;color:#cbd5e1;">
                <li><strong>230,000+ CVE entries</strong> as of April 2026</li>
                <li><strong>~25,000–30,000 new CVEs published per year</strong> in recent years</li>
                <li>Coverage spans <strong>every major software and hardware vendor</strong> globally</li>
                <li>CVSS v3.1 scores available for all CVEs published since 2015; partial v3.0 coverage back to 2005</li>
                <li>Full <strong>REST API</strong> with JSON responses, supporting CVE lookup by ID, keyword, CVSS score range, CWE, CPE, and date range</li>
                <li>Our dataset uses CVSS scores for the <strong>99 of 100 KEV entries</strong> with available NVD scoring (mean Base Score: 8.76 — squarely in the High/Critical range)</li>
            </ul>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="sub-header">🎯 Why We Selected This Source</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            NVD was selected as our scoring enrichment layer for four reasons:
            <br><br>
            <strong>1. Government Standard:</strong> NIST CVSS scores are the mandated scoring
            standard under NIST SP 800-53 (Control RA-3), NIST SP 800-171, and DoD RMF.
            Using NVD scores ensures our risk assessments are auditable and compliant with
            federal frameworks.
            <br><br>
            <strong>2. Diamond Model — Capability Scoring:</strong> CVSS Exploitability sub-scores
            (Attack Vector, Complexity, Privileges Required) directly quantify how accessible an
            adversary's capability is. A CVE with Exploitability 3.9 (network, low complexity,
            no privileges) represents a significantly higher-priority capability for actors like
            Volt Typhoon or APT29 than one requiring local access.
            <br><br>
            <strong>3. Enables Objective Prioritization:</strong> Without CVSS scores, patch
            prioritization is based solely on categorical severity labels. NVD scores allow
            analysts to rank vulnerabilities numerically and justify remediation sequencing
            in POAM documentation.
            <br><br>
            <strong>4. Universal Interoperability:</strong> CVSS is understood by every
            vulnerability scanner, SIEM, and ticketing system in the defense ecosystem —
            Tenable, Qualys, Rapid7, Splunk, ServiceNow. Using NVD scores ensures
            our risk data integrates seamlessly with existing toolchains.
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="sub-header">🏢 Industry Adoption</div>', unsafe_allow_html=True)
        adopters2 = [
            ("DoD Risk Management Framework (RMF)", "NIST SP 800-37 and DoD Instruction 8510.01 mandate CVSS-based risk scoring as part of system authorization (ATO) packages. CVSS scores from NVD are the accepted reference."),
            ("CMMC 2.0 / NIST SP 800-171", "CVSS scores inform the vulnerability management practices required under NIST SP 800-171 control 3.11.2 (Scan for Vulnerabilities) and 3.11.3 (Remediate Vulnerabilities)."),
            ("Tenable / Qualys / Rapid7", "All major vulnerability scanners use NVD CVSS scores as the default severity baseline. Tenable's VPR (Vulnerability Priority Rating) supplements CVSS with threat intelligence weighting."),
            ("Microsoft / Cisco / Fortinet", "Vendor security advisories reference NVD CVE entries and CVSS scores as the authoritative severity metric for their own product vulnerability disclosures."),
            ("SIEM Platforms (Splunk, Sentinel)", "NVD CVSS data is ingested as enrichment to auto-score vulnerability-related alerts and prioritize incident response queues."),
            ("Academic & Policy Research", "NVD is the primary empirical dataset used in peer-reviewed cybersecurity research measuring vulnerability severity distributions, time-to-patch trends, and vendor disclosure practices."),
        ]
        for org, reason in adopters2:
            st.markdown(f"""
            <div style="display:flex;gap:1rem;padding:0.6rem 0;border-bottom:1px solid #1e293b;
                        align-items:flex-start;">
                <span style="font-size:0.78rem;font-weight:700;color:#34d399;min-width:220px;
                             padding-top:0.05rem;">{org}</span>
                <span style="font-size:0.82rem;color:#94a3b8;line-height:1.5;">{reason}</span>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown('<div class="sub-header">🔄 Collection Strategy & Integration</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        <strong>Source:</strong> NIST NVD REST API at
        <code style="background:rgba(52,211,153,0.1);padding:1px 6px;border-radius:4px;color:#6ee7b7;">
        https://services.nvd.nist.gov/rest/json/cves/2.0
        </code>
        <br><br>
        <strong>Our pipeline:</strong> CVSS v3.1 Base Score, Impact Score, and Exploitability Score
        were retrieved for each of the 100 KEV entries in our dataset using CVE ID lookups against
        the NVD API. Results were stored in
        <code style="background:rgba(52,211,153,0.1);padding:1px 6px;border-radius:4px;color:#6ee7b7;">
        Data_with_Scores.json</code> and merged with
        <code style="background:rgba(52,211,153,0.1);padding:1px 6px;border-radius:4px;color:#6ee7b7;">
        Defense_KEV_Entries.json</code> on CVE ID for dashboard display.
        <br><br>
        <strong>Minimum data expectations:</strong> Each entry requires a valid CVSS v3.1 Base Score
        (0.0–10.0), Impact Score, and Exploitability Score. Entries where NVD analysis is pending
        (status: "Awaiting Analysis") are included with a null score and flagged in the dashboard
        as unscored. One entry in the 100-CVE dataset falls into this category.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📚 References", expanded=False):
            for label, url in [
                ("NIST NVD — National Vulnerability Database", "https://nvd.nist.gov"),
                ("NIST NVD REST API Documentation", "https://nvd.nist.gov/developers/vulnerabilities"),
                ("CVSS v3.1 Specification (FIRST)", "https://www.first.org/cvss/specification-document"),
                ("NIST SP 800-171 Rev 3 — Protecting CUI", "https://csrc.nist.gov/pubs/sp/800/171/r3/final"),
                ("NIST SP 800-37 Rev 2 — Risk Management Framework", "https://csrc.nist.gov/pubs/sp/800/37/r2/final"),
                ("CMMC 2.0 Final Rule (32 CFR Part 170)", "https://www.federalregister.gov/documents/2024/10/15/2024-21165/cybersecurity-maturity-model-certification-cmmc-program"),
            ]:
                st.markdown(f"""
                <div style="background:rgba(52,211,153,0.05);border:1px solid rgba(52,211,153,0.15);
                            border-left:3px solid #34d399;border-radius:0 10px 10px 0;
                            padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.76rem;
                                 color:#34d399;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank"
                       style="font-size:0.74rem;color:#34d399;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════
    # TAB 3 — COLLECTION STRATEGIES & DATA SUMMARY
    # ════════════════════════════════════════════════════════════════════
    with tab3:

        st.markdown("""
        <div style="background:rgba(168,85,247,0.06);border:1px solid rgba(192,132,252,0.2);
                    border-left:4px solid #a855f7;border-radius:0 12px 12px 0;
                    padding:1.2rem 1.5rem;margin-bottom:1.5rem;">
            <div style="font-family:'Space Mono',monospace;font-size:1rem;font-weight:700;
                         color:#a855f7;margin-bottom:0.3rem;">
                Collection Strategies & Dataset Summary
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6;">
                End-to-end documentation of how each data source was collected, the analytical
                approaches used, comparisons to similar industry pipelines, and a full summary of the final dataset.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sub-header">🔄 Collection Pipeline: Step-by-Step</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        The dataset powering this dashboard was assembled through a <strong>three-stage pipeline</strong>:
        automated API collection, filter-based curation, and cross-source enrichment. Each stage is
        described below.
        <br><br>

        <strong>Stage 1 — Bulk Acquisition (CISA KEV JSON Feed)</strong><br>
        The full CISA KEV catalog was retrieved as a single JSON file from CISA's static feed endpoint:
        <code style="background:rgba(168,85,247,0.12);padding:1px 6px;border-radius:4px;color:#d8b4fe;">
        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json</code>.
        This is a flat-file bulk download (not paginated), so the entire catalog — all 1,500+ entries —
        is acquired in a single HTTP GET request. The file is refreshed by CISA whenever new entries
        are added, meaning a scheduled daily or weekly pull is sufficient to stay current. No
        authentication, API key, or rate-limiting applies to this endpoint.
        <br><br>

        <strong>Stage 2 — Defense-Sector Curation (Filter Logic)</strong><br>
        The raw KEV catalog was filtered down to <strong>100 defense/government-relevant entries</strong>
        using a tiered selection criteria:
        <ul style="margin-top:0.5rem;padding-left:1.2rem;color:#cbd5e1;">
            <li><strong>Criterion 1 — Governing Directive:</strong> Entries must be governed by
            BOD 22-01 or an Emergency Directive (ED 25-02, ED 25-03, ED 26-03).</li>
            <li><strong>Criterion 2 — Sector Prevalence:</strong> Vendor and product fields were
            cross-referenced against the DISA Approved Products List (APL) and publicly known
            DoD/FCEB IT stacks.</li>
            <li><strong>Criterion 3 — Ransomware Flag:</strong> Entries with
            <code style="background:rgba(168,85,247,0.12);padding:1px 4px;border-radius:3px;color:#d8b4fe;">
            knownRansomwareCampaignUse: "Known"</code> were prioritized.</li>
            <li><strong>Criterion 4 — Severity Gate:</strong> Only Critical or High severity
            entries were retained.</li>
        </ul>
        <br>

        <strong>Stage 3 — CVSS Enrichment (NIST NVD API)</strong><br>
        For each of the 100 curated KEV entries, a CVE ID lookup was performed against the
        NVD REST API endpoint:
        <code style="background:rgba(168,85,247,0.12);padding:1px 6px;border-radius:4px;color:#d8b4fe;">
        https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX</code>.
        Three CVSS v3.1 sub-scores were extracted per entry: Base Score, Impact Score, and
        Exploitability Score. Results were merged with the KEV entries on CVE ID to produce
        <code style="background:rgba(168,85,247,0.12);padding:1px 6px;border-radius:4px;color:#d8b4fe;">
        Data_with_Scores.json</code>.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">🧠 Why These Collection Approaches?</div>', unsafe_allow_html=True)

        c1, c2 = st.columns(2)

        with c1:
            st.markdown("""
            <div class="info-box">
            <strong>Why bulk JSON download over a streaming or scraping approach?</strong><br>
            CISA publishes the KEV catalog as a single machine-readable JSON file specifically to
            encourage programmatic consumption. Scraping the human-facing web catalog would be
            fragile (subject to HTML changes), slower, and violates CISA's intended use model.
            Bulk JSON download is also reproducible: the same URL always returns the complete
            catalog at a point in time, making dataset versioning straightforward.
            <br><br>
            <strong>Why REST API for NVD instead of a bulk NVD data dump?</strong><br>
            NIST does publish annual NVD data feeds (JSON files by year), but these are only
            updated once per day and require downloading gigabytes of data to retrieve scores
            for 100 specific CVEs. The REST API allows targeted per-CVE retrieval, dramatically
            reducing bandwidth and processing time. For datasets under ~500 CVEs, the API approach
            is universally preferred in practice — even in commercial SIEM integrations.
            <br><br>
            <strong>Why filter to 100 entries?</strong><br>
            The full KEV catalog (~1,500 entries) spans vulnerabilities dating to 2002, many of
            which affect software no longer present in modern defense IT environments. Filtering
            to 100 entries ensures the dashboard remains operationally relevant — focused on
            vulnerabilities that are both actively mandated and present in real DoD/DIB systems
            as of 2024–2026.
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown("""
            <div class="info-box">
            <strong>Why CVSS v3.1 and not v4.0?</strong><br>
            CVSS v4.0 was published by FIRST in October 2023, but as of April 2026 it has not yet
            been adopted as the NVD scoring standard — NVD continues to publish v3.1 as the primary
            score for new CVEs. More importantly, all federal compliance frameworks (NIST SP 800-53,
            RMF, CMMC 2.0) reference CVSS v3.x thresholds in their severity classification tables.
            <br><br>
            <strong>Why not use commercial CTI feeds (CrowdStrike, Recorded Future, Mandiant)?</strong><br>
            Commercial threat intelligence platforms provide richer context but require expensive
            subscription licenses and often impose redistribution restrictions on derived data.
            For a government-sector dashboard intended to be shareable with DoD stakeholders,
            open government sources (CISA, NIST) are preferred because they carry no licensing
            encumbrances, can be cited in official documentation, and are trusted by auditors
            and contracting officers by default.
            <br><br>
            <strong>Why not include MITRE ATT&CK TTP data in the enrichment layer?</strong><br>
            ATT&CK TTP mappings were considered for enrichment but ultimately deferred to the
            Diamond Model pages of this dashboard, where TTP context is presented in the actor
            analysis workflow. Mixing TTP data into the vulnerability dataset would conflate
            two distinct analytical layers (capability vs. technique), reducing clarity.
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">🏭 Do Others Use Similar Collection Approaches?</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        Yes — the KEV + NVD enrichment pipeline used here is a well-established pattern in both
        commercial security tooling and academic CTI research. The following documented implementations
        follow comparable architectures:
        </div>
        """, unsafe_allow_html=True)

        comparables = [
            (
                "Tenable Vulnerability Intelligence (VPR Model)",
                "Tenable's Vulnerability Priority Rating (VPR) ingests CISA KEV status and NVD CVSS scores as two of its core input signals, combining them with Tenable's own threat actor telemetry and exploit availability data to produce a composite risk score.",
                "Tenable Research: VPR — https://www.tenable.com/blog/what-is-vpr-and-how-is-it-different-from-cvss"
            ),
            (
                "CISA SSVC Decision Trees (Stakeholder-Specific Vulnerability Categorization)",
                "CISA's own SSVC framework (published 2022) uses KEV catalog membership as a primary decision node in its vulnerability triage decision tree, combined with NVD exploitation likelihood data. Our filter-based curation approach is aligned with SSVC's 'Prioritize' outcome criteria.",
                "CISA SSVC Guide — https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide-508c.pdf"
            ),
            (
                "MITRE Engenuity — ATT&CK Evaluations (KEV Alignment)",
                "MITRE's ATT&CK Evaluations program cross-references KEV catalog entries against evaluated adversary TTPs to identify which vendor products are most exposed to APT-associated CVEs. Their methodology mirrors our Stage 2 filter logic: KEV membership + sector prevalence + actor mapping.",
                "MITRE ATT&CK Evaluations — https://attackevals.mitre-engenuity.org"
            ),
            (
                "Rapid7 AttackerKB & Metasploit",
                "Rapid7's AttackerKB platform combines NVD CVSS data with community-sourced attacker assessments of exploitability, and their Metasploit team uses KEV membership as a prioritization signal when deciding which CVEs to develop public exploit modules for.",
                "Rapid7 Vulnerability Intelligence Report — https://www.rapid7.com/research/report/vulnerability-intelligence-report/"
            ),
            (
                "Academic Research (Carnegie Mellon CERT/CC)",
                "CMU CERT/CC's Exploit Prediction Scoring System (EPSS) uses NVD CVSS metrics as feature inputs to a machine learning model that predicts the probability of a CVE being exploited in the wild within 30 days. KEV catalog membership is used as the ground-truth exploitation label.",
                "EPSS Model — https://www.first.org/epss/model"
            ),
            (
                "Coalfire / Schellman — FedRAMP/CMMC Compliance Tooling",
                "Major federal compliance assessors use KEV + NVD score pipelines in their automated vulnerability management workflows to auto-populate POAM entries during RMF Authorization to Operate (ATO) assessments. Our pipeline directly mirrors the data model used in these compliance tools.",
                "CMMC Assessment Guide Level 2 — https://dodcio.defense.gov/CMMC/Documentation/"
            ),
        ]

        for org, desc, ref in comparables:
            st.markdown(f"""
            <div style="background:rgba(168,85,247,0.05);border:1px solid rgba(192,132,252,0.15);
                        border-left:3px solid #a855f7;border-radius:0 10px 10px 0;
                        padding:0.9rem 1.1rem;margin:0.5rem 0;">
                <div style="font-size:0.82rem;font-weight:700;color:#c084fc;margin-bottom:0.4rem;">
                    {org}
                </div>
                <div style="font-size:0.80rem;color:#94a3b8;line-height:1.55;margin-bottom:0.4rem;">
                    {desc}
                </div>
                <div style="font-size:0.72rem;color:#7c3aed;font-style:italic;">
                    📎 {ref}
                </div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">📦 Dataset Summary</div>', unsafe_allow_html=True)

        k1, k2, k3, k4, k5 = st.columns(5)
        summary_kpis = [
            (k1, "100", "Total CVE Records", "Defense/govt-curated"),
            (k2, "99", "CVSS-Scored Entries", "1 awaiting NVD analysis"),
            (k3, "8.76", "Mean CVSS Base Score", "High/Critical range"),
            (k4, "2002–2024", "Vulnerability Date Range", "CVE disclosure years"),
            (k5, "2", "Source Datasets Merged", "KEV + NVD"),
        ]
        for col, val, label, delta in summary_kpis:
            with col:
                st.markdown(f"""
                <div style="background:rgba(168,85,247,0.06);border:1px solid rgba(192,132,252,0.18);
                            border-radius:12px;padding:1rem 1.2rem;text-align:center;">
                    <div style="font-family:'Space Mono',monospace;font-size:1.5rem;
                                 font-weight:700;color:#a855f7;line-height:1.1;">{val}</div>
                    <div style="font-size:0.68rem;color:#64748b;text-transform:uppercase;
                                 letter-spacing:0.07em;margin-top:0.3rem;">{label}</div>
                    <div style="font-size:0.68rem;color:#f97316;margin-top:0.2rem;">{delta}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        metadata = pd.DataFrame({
            "Field": [
                "cveID", "vendorProject", "product", "vulnerabilityName",
                "dateAdded", "dueDate", "shortDescription", "requiredAction",
                "knownRansomwareCampaignUse", "notes", "cwes",
                "severity", "governing_directive",
                "cvss_base_score", "cvss_impact_score", "cvss_exploitability_score"
            ],
            "Source": [
                "CISA KEV", "CISA KEV", "CISA KEV", "CISA KEV",
                "CISA KEV", "CISA KEV", "CISA KEV", "CISA KEV",
                "CISA KEV", "CISA KEV", "CISA KEV",
                "CISA KEV (derived)", "CISA KEV (derived)",
                "NIST NVD", "NIST NVD", "NIST NVD"
            ],
            "Type": [
                "String (CVE ID)", "String", "String", "String",
                "Date (YYYY-MM-DD)", "Date (YYYY-MM-DD)", "Text", "Text",
                "Categorical (Known / Unknown)", "Text (nullable)", "String (CWE-XXX)",
                "Categorical (Critical / High)", "String (BOD / ED number)",
                "Float (0.0–10.0)", "Float (0.0–10.0)", "Float (0.0–3.9)"
            ],
            "Null Rate": [
                "0%", "0%", "0%", "0%",
                "0%", "0%", "0%", "0%",
                "0%", "~40% (expected)", "~5%",
                "0%", "0%",
                "1% (1 entry)", "1% (1 entry)", "1% (1 entry)"
            ],
            "Notes": [
                "Primary join key (e.g., CVE-2021-44228)", "e.g., Microsoft, Cisco, Fortinet",
                "e.g., Windows Server, FortiOS, ESXi", "Human-readable vuln name",
                "Date CISA added to KEV catalog", "BOD/ED mandated remediation deadline",
                "CISA-authored plain-language description", "CISA recommended remediation step",
                "Whether ransomware groups have used this CVE", "Additional context (often blank)",
                "CWE weakness class (e.g., CWE-79, CWE-20)", "Derived from CISA severity field",
                "Governing BOD or Emergency Directive", "NVD overall severity score",
                "Consequences to CIA triad if exploited", "How easily the flaw can be triggered"
            ]
        })

        st.dataframe(metadata, use_container_width=True, hide_index=True)

        st.markdown("<br>", unsafe_allow_html=True)

        c1, c2 = st.columns(2)

        with c1:
            st.markdown('<div class="sub-header">📅 Date Coverage</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The 100-entry curated dataset spans CVEs originally disclosed between
            <strong>2002 and 2024</strong>, though the majority cluster in the 2018–2023 window
            when the defense sector's attack surface expanded significantly due to cloud adoption,
            remote access proliferation (Pulse, Citrix, Ivanti), and the Log4Shell supply chain event.
            <br><br>
            Key temporal reference points:
            <ul style="margin-top:0.5rem;padding-left:1.2rem;color:#cbd5e1;">
                <li><strong>Earliest CVE:</strong> 2002 (legacy Windows/Cisco vulnerabilities
                retained due to continued presence in legacy DoD systems)</li>
                <li><strong>Most active disclosure window:</strong> 2019–2023</li>
                <li><strong>KEV catalog date added range:</strong> November 2021 through April 2026</li>
                <li><strong>Due dates:</strong> Range from 2-week emergency windows to
                6-month standard remediation timelines</li>
            </ul>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown('<div class="sub-header">🏷️ Key Metadata Fields for Analysis</div>', unsafe_allow_html=True)
            st.markdown("""
            <div class="info-box">
            The following fields are most analytically significant for the CTI use cases in this dashboard:
            <br><br>
            <strong>knownRansomwareCampaignUse:</strong> Binary signal that separates purely
            nation-state-exploited CVEs from those also weaponized by financially motivated actors.
            Roughly 40% of the 100-entry dataset carries a "Known" ransomware flag.
            <br><br>
            <strong>cvss_exploitability_score:</strong> The most operationally useful sub-score
            for patch sequencing. Vulnerabilities with Exploitability ≥ 3.5 represent the
            highest-urgency remediation targets. The dataset mean exploitability is approximately 3.4.
            <br><br>
            <strong>cwes:</strong> CWE classifications reveal which weakness classes dominate
            the defense attack surface. The most frequent in this dataset are CWE-89 (SQL Injection),
            CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation), and CWE-287
            (Improper Authentication).
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">⚠️ Dataset Limitations & Caveats</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        <strong>1. Curation Bias:</strong> The 100-entry subset was manually curated using
        sector-prevalence criteria, introducing selection bias toward well-known enterprise products.
        <br><br>
        <strong>2. CVSS Does Not Equal Exploitability in Context:</strong> CVSS base scores
        measure theoretical worst-case severity in isolation from compensating controls.
        <br><br>
        <strong>3. KEV Is Not Exhaustive:</strong> The KEV catalog only includes vulnerabilities
        with confirmed exploitation evidence reviewed by CISA. Nation-state LotL activity may
        exploit CVEs not yet in KEV.
        <br><br>
        <strong>4. Temporal Snapshot:</strong> The dataset represents a static snapshot curated
        as of April 2026.
        <br><br>
        <strong>5. One Unscored Entry:</strong> One of the 100 KEV entries returned an
        "Awaiting Analysis" status from NVD at time of collection.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">🕐 Minimum Data Expectations</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="info-box">
        The reason our data is limited to ~100 items is because of the time frame and scope of our platform.
        Since CTI is constantly changing, making sure the data we present is accurate and relevant to
        present day's cyber threat landscape meant that our time frame for each vulnerability was
        discovered or posted within the last year (from January 2025 to April 2026). Second, our scope
        is limited to vendors of defense contractors which limits the number of CVEs from NIST and CISA
        we analyzed. But, even with our limitations, this platform remains relevant because of how
        recent these vulnerabilities were acknowledged and posted to government cybersecurity databases.
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📚 References for Collection Methods & Comparable Pipelines", expanded=False):
            for label, url in [
                ("CISA KEV JSON Feed (machine-readable bulk download)", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
                ("NIST NVD REST API v2.0 Documentation", "https://nvd.nist.gov/developers/vulnerabilities"),
                ("CISA SSVC Prioritization Guide (KEV + Exploitation Decision Trees)", "https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide-508c.pdf"),
                ("FIRST EPSS — Exploit Prediction Scoring System (NVD + KEV ML model)", "https://www.first.org/epss/model"),
                ("Tenable VPR — Vulnerability Priority Rating Methodology", "https://www.tenable.com/blog/what-is-vpr-and-how-is-it-different-from-cvss"),
                ("Rapid7 Vulnerability Intelligence Report", "https://www.rapid7.com/research/report/vulnerability-intelligence-report/"),
                ("MITRE ATT&CK Evaluations — KEV-ATT&CK Cross-Mapping", "https://attackevals.mitre-engenuity.org"),
                ("Exploit-DB — Open Source Exploit Repository (PoC Availability Source)", "https://www.exploit-db.com"),
                ("RansomWatch — Open Source Ransomware Leak Site Tracker", "https://ransomwatch.telemetry.ltd"),
                ("CVSS v3.1 Specification (FIRST)", "https://www.first.org/cvss/specification-document"),
                ("DISA APL — Approved Products List (Defense Sector IT Stack Reference)", "https://aplits.disa.mil/processAPList.action"),
                ("CMMC Assessment Guide Level 2 (Compliance Pipeline Reference)", "https://dodcio.defense.gov/CMMC/Documentation/"),
            ]:
                st.markdown(f"""
                <div style="background:rgba(168,85,247,0.04);border:1px solid rgba(192,132,252,0.12);
                            border-left:3px solid #7c3aed;border-radius:0 10px 10px 0;
                            padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.76rem;
                                 color:#a855f7;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank"
                       style="font-size:0.74rem;color:#7c3aed;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════
    # TAB 4 — METRICS & VALIDATION
    # ════════════════════════════════════════════════════════════════════
    with tab4:

        st.markdown("""
        <div style="background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.2);
                    border-left:4px solid #fbbf24;border-radius:0 12px 12px 0;
                    padding:1.2rem 1.5rem;margin-bottom:1.5rem;">
            <div style="font-family:'Space Mono',monospace;font-size:1rem;font-weight:700;
                         color:#fbbf24;margin-bottom:0.3rem;">
                Operational Metrics, Preliminary Visualizations & Validation
            </div>
            <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6;">
                CTI program evaluation metrics mapped to real defense sector use cases,
                two preliminary visualizations supporting intelligence delivery, and a
                brief validation and error analysis of the platform's dataset and methodology.
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")
        st.markdown('<div class="sub-header">🔍 Validation & Error Analysis</div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong style="color:#38bdf8;">Assumptions</strong><br><br>
            • Threat actor attribution is based on public government attribution (CISA, FBI, NSA,
            MITRE ATT&CK) — not independent analysis<br><br>
            • Likelihood and impact scores in the threat model are researcher-assigned based on
            documented incident frequency, not statistically derived from a formal model<br><br>
            • Vendor-to-contractor mapping is based on publicly known deployments (CISA advisories,
            CSIS incidents) — not confirmed inventory from any specific organization<br><br>
            • KEV catalog membership is treated as a reliable proxy for confirmed active exploitation
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong style="color:#fbbf24;">Limitations</strong><br><br>
            • Platform uses a static data snapshot as of April 2026 — KEV, advisories, and
            CSIS incidents update continuously and will not be reflected without a data refresh<br><br>
            • 100-entry KEV dataset introduces selection bias toward well-known enterprise vendors
            (Microsoft, Cisco, Fortinet) — specialized defense platform CVEs (SCADA, embedded
            firmware) may be underrepresented<br><br>
            • KEV only reflects confirmed exploitation — nation-state LotL activity (e.g., Volt
            Typhoon) may exploit CVEs that have not generated sufficient public reporting to
            trigger KEV addition<br><br>
            • CVSS scores measure theoretical worst-case severity, not contextual risk within
            a specific contractor environment
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong style="color:#fbbf24;">Error Sources</strong><br><br>
            • One NVD entry returned "Awaiting Analysis" — retained with null CVSS scores,
            flagged in the dashboard for analyst awareness<br><br>
            • Exploitation intensity scores are researcher-assigned ordinal values, not derived
            from a quantitative model — subject to analyst interpretation bias<br><br>
            • Dwell time estimates for MTTD baseline (e.g., Volt Typhoon "up to 5 years")
            are upper bounds from CISA advisories, not population averages
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="info-box">
            <strong style="color:#38bdf8;">Validation Method</strong><br><br>
            • <strong>Cross-source consistency:</strong> Each threat scenario validated against
            at least two independent sources (e.g., CISA advisory + MITRE ATT&CK + CSIS)<br><br>
            • <strong>Spot-check:</strong> Boeing/Citrix Bleed corroborated across CISA AA23-325A,
            CSIS incident timeline, and MITRE ATT&CK T1190<br><br>
            • <strong>SolarWinds spot-check:</strong> APT29/SUNBURST corroborated across
            FireEye/Mandiant disclosure, CISA ED 21-01, and MITRE ATT&CK G0016
        </div>
        """, unsafe_allow_html=True)