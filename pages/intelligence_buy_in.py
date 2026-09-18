import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json


def render():

    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@400;500;600&display=swap');

    .dash-section-header {
        font-family: 'Space Mono', monospace;
        font-size: 1.15rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.04em;
        margin-bottom: 0.5rem;
        text-transform: uppercase;
    }
    </style>
    """, unsafe_allow_html=True)

    def section_header(label, emoji=""):
        prefix = f"{emoji} " if emoji else ""
        st.markdown(
            f'<div class="dash-section-header">{prefix}{label}</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-header">📄 Intelligence Buy-In: The Case for Defense Vendors</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box" style="font-size:1rem;padding:1.2rem 1.5rem"> 
    <strong style="color:#38bdf8;font-size:1.1rem">"Security without intelligence is just expensive guessing."</strong><br><br>
    This section presents the business case for dedicating investments in a cyber threat intelligence platform 
    tailored for vendors of defense contractors (e.g., Lockheed Martin, Boeing, Leidos) — grounded in breach cost data, threat landscape trends, and ROI modeling.
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sub-header">Current Threat Landscape</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="threat-box">
        <strong>Threats to Defense's Vendors</strong>
            <br><br>
                Vendors such as Microsoft, Amazon Web Services, and Google Cloud all provide services to support defense contractors. They occupy a uniquely critical position in the defense ecosystem. 
                While they are not directly building weapons systems like Lockheed Martin or Boeing, they provide the digital infrastructure, cloud environments, AI platforms, and productivity tools that enable those contractors to operate. 
                This makes vendors high-value targets for cybercriminals and nation-state actors. 
                A successful breach of a vendor can create a cascading effect, granting attackers indirect access to multiple defense organizations simultaneously through shared services, APIs, or supply chain integrations.
            <br><br>
        <strong>Threats in Reality</strong>
        <br><br>
                Threat actors frequently exploit this by targeting vendor-managed services, software updates, or identity systems—commonly referred to as supply chain attacks. 
                The SolarWinds cyberattack is a prime example, where attackers compromised a trusted vendor to infiltrate numerous government and private-sector networks. 
                For vendors supporting defense, the stakes are even higher because compromised systems may expose sensitive defense-related data, operational capabilities, or intellectual property.
        <br><br>   
                In a supply chain attack scenario, adversaries target a vendor rather than a hardened defense contractor directly. 
                By compromising a shared software update system or cloud service, attackers can gain access to multiple downstream organizations.
                <br><br>
                The SolarWinds attack demonstrated how a single vendor compromise enabled access to numerous government and defense-related systems.
                <br><br>
                With mature CTI capabilities:
                <ul>
                    <li>Indicators of compromise can be identified earlier across global telemetry</li>
                    <li>Threat campaigns can be detected before widespread propagation</li>
                    <li>Mitigations can be deployed simultaneously across all customers</li>
                </ul>
                This "detect once, protect many" model is where vendors realize exponential ROI from threat intelligence investments.
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sub-header">How CTI Reduces Breach Costs</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="asset-box">
        Vendors supporting defense contractors face amplified financial risk due to their role in the supply chain—one compromise can impact multiple customers simultaneously.
        <br><br>
        According to IBM's Cost of a Data Breach Report, the average breach costs USD 4.44 million, with detection and escalation alone costing USD 1.47 million.
        <br><br>
        Organizations that implement security AI and automation reduce breach lifecycle time by 77 days (247 vs. 324 days), resulting in average savings of approximately USD 1.76 million per breach.
        <br><br>
        Threat intelligence platforms directly contribute to these savings by:
        <ul>
            <li>Reducing Mean Time to Detect (MTTD) by up to 50%</li>
            <li>Reducing Mean Time to Respond (MTTR) by 30–60%</li>
            <li>Lowering false positives by 40% or more through contextual intelligence</li>
        </ul>
        <br>
        For vendors operating at scale, these efficiencies multiply across customers—turning CTI into a high-return investment rather than a cost center.
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sub-header">CTI Roadmap for Vendors</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="asset-box">
        <ol>
            <li><strong>Planning:</strong> Vendors align intelligence requirements not just internally, but across customer environments and shared infrastructure dependencies.</li>
            <li><strong>Threat Data Collection:</strong> Collection spans endpoints, cloud workloads, identity systems, and global telemetry across all tenants.</li>
            <li><strong>Processing:</strong> Data is normalized and enriched using frameworks like MITRE ATT&CK, enabling cross-customer correlation and detection of large-scale campaigns.</li>
            <li><strong>Analysis:</strong> Analysts identify patterns across multiple organizations, uncovering supply chain threats and nation-state activity earlier than isolated defenders could.</li>
            <li><strong>Dissemination:</strong> Intelligence is distributed both internally and to customers via platforms, dashboards, and automated security controls.</li>
            <li><strong>Feedback:</strong> Continuous feedback loops refine detections across the entire ecosystem, improving protection for all connected defense clients.</li>
        </ol>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sub-header">Quantifying CTI ROI for Vendors</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="asset-box">
        <strong>Direct Cost Reduction</strong><br>
        <ul>
            <li>$1.76M average savings per breach with AI + automation (IBM)</li>
            <li>20–30% reduction in incident response costs through faster triage and prioritization</li>
        </ul>
        <strong>Operational Efficiency</strong>
        <ul>
            <li>40–60% reduction in analyst investigation time (Gartner / industry estimates)</li>
            <li>30–50% fewer alerts requiring manual review due to intelligence enrichment</li>
            <li>Up to 2–3x increase in analyst productivity through automation and correlation</li>
        </ul>
        <strong>Risk Reduction</strong>
        <ul>
            <li>50% faster detection of advanced threats using behavior-based intelligence</li>
            <li>Significant reduction in lateral movement due to earlier containment</li>
            <li>Lower probability of supply chain compromise impacting multiple customers</li>
        </ul>
        <strong>Revenue Protection & Trust</strong>
        <ul>
            <li>Avoidance of contract penalties and SLA breaches</li>
            <li>Preservation of high-value defense contracts and certifications (e.g., CMMC)</li>
            <li>Reduced likelihood of reputational damage across the defense ecosystem</li>
        </ul>
        <strong>= Measurable ROI</strong><br>
        For vendors managing multiple defense clients, preventing even a single large-scale breach—or reducing its scope—can yield multi-million dollar savings, making CTI programs one of the highest ROI investments in cybersecurity.
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sub-header">Changing Security Strategy: Vendor Reality</div>', unsafe_allow_html=True)
    strategy_cols = st.columns(3)
    with strategy_cols[0]:
        st.markdown("""
        <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:12px;padding:1rem;text-align:center">
            <div style="font-size:1.5rem">❌</div>
            <div style="font-family:Space Mono,monospace;font-size:0.85rem;color:#f87171;margin:0.4rem 0">REACTIVE</div>
            <div style="font-size:0.82rem;color:#ffffff">Respond after customer impact. Patch after exploitation spreads across tenants.</div>
        </div>
        """, unsafe_allow_html=True)
    with strategy_cols[1]:
        st.markdown("""
        <div style="background:rgba(251,191,36,0.08);border:1px solid rgba(251,191,36,0.25);border-radius:12px;padding:1rem;text-align:center">
            <div style="font-size:1.5rem">⚠️</div>
            <div style="font-family:Space Mono,monospace;font-size:0.85rem;color:#fbbf24;margin:0.4rem 0">PROACTIVE</div>
            <div style="font-size:0.82rem;color:#ffffff">Harden platforms and monitor continuously, but still limited to known threats.</div>
        </div>
        """, unsafe_allow_html=True)
    with strategy_cols[2]:
        st.markdown("""
        <div style="background:rgba(52,211,153,0.08);border:1px solid rgba(52,211,153,0.25);border-radius:12px;padding:1rem;text-align:center">
            <div style="font-size:1.5rem">✅</div>
            <div style="font-family:Space Mono,monospace;font-size:0.85rem;color:#34d399;margin:0.4rem 0">INTELLIGENCE-LED</div>
            <div style="font-size:0.82rem;color:#ffffff">Leverage global telemetry to anticipate campaigns, stop threats upstream, and protect all customers simultaneously.</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="sub-header">Vendor Recommendations: Driving ROI</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="asset-box">
        <strong>Automation & AI at Scale</strong><br>
        Vendors must process massive volumes of telemetry across distributed environments. AI-driven platforms such as Microsoft Defender and Sentinel enable automated detection and response across billions of signals.
        <br><br>
        IBM research shows organizations with fully deployed AI and automation reduce breach lifecycle time by nearly 24%, significantly lowering response costs and operational impact.
        <br><br>
        <strong>Supply Chain Security & Compliance</strong><br>
        Vendors must meet strict frameworks like CMMC and NIST SP 800-161, ensuring protection of Controlled Unclassified Information (CUI) across the defense supply chain. 
        Compliance is not just regulatory—it is a competitive differentiator for securing defense contracts.
        <br><br>
        <strong>Shared Intelligence = Exponential Value</strong><br>
        Unlike individual contractors, vendors gain visibility across multiple organizations. 
        This allows threat intelligence to scale horizontally—detecting threats once and protecting many—dramatically increasing return on investment.
        <br><br>
        <strong>= Cyber Resilience at Ecosystem Scale</strong><br>
        Strong CTI programs enable vendors to act as security force multipliers, reducing systemic risk across the entire defense industrial base while improving cost efficiency and response speed.
    </div>
    """, unsafe_allow_html=True)

    # ── Sources (expandable) ──────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("📚 Sources & References", expanded=False):
        sources = [
            {
                "label": "IBM - Cost of a Data Breach Report 2025",
                "url": "https://www.ibm.com/reports/data-breach",
            },
            {
                "label": "Microsoft - Digital Defense Report 2025",
                "url": "https://www.microsoft.com/en-us/corporate-responsibility/cybersecurity/microsoft-digital-defense-report-2025/",
            },
            {
                "label": "Google Cloud - Beyond the Battlefield: Threats to the Defense Industrial Base",
                "url": "https://cloud.google.com/blog/topics/threat-intelligence/threats-to-defense-industrial-base",
            },
            {
                "label": "National Institute of Standards and Technology - NIST SP 800-161 Rev. 1",
                "url": "https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final",
            },
            {
                "label": "Cybersecurity & Infrastructure Security Agency - Information and Communications Technology Supply Chain Risk Management",
                "url": "https://www.cisa.gov/information-and-communications-technology-supply-chain-risk-management",
            },
            {
                "label": "MITRE ATT&CK Framework",
                "url": "https://attack.mitre.org/",
            },
            {
                "label": "US Department of Defense - CMMC",
                "url": "https://dodcio.defense.gov/Portals/0/Documents/CMMC/CMMC-FAQsv3.pdf",
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