import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def render():

    # ── CSS ───────────────────────────────────────────────────────────────────
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

    st.markdown('<div class="section-header">🚀 Future CTI Platform Directions</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box">
    The current platform delivers a strong foundation for defense vendor CTI analysis —
    but three high-impact development directions would transform it from a
    <strong>static intelligence dashboard</strong> into a
    <strong>live, automated, analyst-grade CTI operations platform</strong>.
    Each direction is grounded in real industry gaps identified through this project's research
    and directly extends the work completed in Milestones 1–3.
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    # ── DIRECTION 1 ──────────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:rgba(56,189,248,0.06);border:1px solid rgba(56,189,248,0.25);
                border-radius:14px;padding:1.5rem 1.8rem;margin:1rem 0;">
        <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
            <div style="font-size:2.2rem">🤖</div>
            <div>
                <div style="font-family:'Space Mono',monospace;font-size:1.05rem;font-weight:700;
                             color:#38bdf8;">Direction 1 — AI-Powered Threat Actor Attribution Assistant</div>
                <div style="font-size:0.82rem;color:#64748b;margin-top:2px;">
                    Natural Language CTI · LLM Integration · Analyst-Facing Intelligence
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([3, 2])
    with col1:
        st.markdown("""
        <div class="info-box">
        <strong style="color:#38bdf8;">What It Is</strong><br><br>
        Integrate a large language model (Claude or GPT-4) directly into the platform so analysts
        can describe an observed TTP, IOC, or behavioral pattern in plain English and receive
        back a <strong>ranked list of probable threat actors</strong> with confidence scores,
        supporting evidence from MITRE ATT&CK, and recommended detection rules — all in seconds.<br><br>
        For example: an analyst types <em>"We observed wmic and certutil being used to download
        a payload from a US-based IP after a Citrix authentication event"</em> and the platform
        returns APT29 and Volt Typhoon as top candidates, explains why based on documented TTPs,
        and suggests Sigma detection rules for the SOC.
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="asset-box">
        <strong style="color:#34d399;">Why It Matters</strong><br><br>
        • Bridges the gap between raw alerts and finished intelligence<br><br>
        • Reduces time-to-attribution from days to minutes<br><br>
        • Makes the platform accessible to junior analysts who lack deep ATT&CK expertise<br><br>
        • Directly improves the Alert Precision metric from Milestone 3<br><br>
        • Positions the platform at the frontier of where the CTI industry is moving
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box" style="margin-top:0.5rem">
    <strong style="color:#38bdf8;">Implementation Path</strong><br><br>
    The Anthropic Claude API or OpenAI GPT-4 API would be called with a structured system prompt
    embedding the platform's threat actor profiles, MITRE ATT&CK TTP mappings, and KEV data as
    context. The analyst's natural language query is passed as the user message. The model returns
    a structured JSON response with ranked actors, confidence scores, and ATT&CK technique matches
    that render as interactive cards in the Streamlit interface. A feedback loop allows analysts
    to confirm or reject attributions, improving future responses. API cost is minimal for
    analyst-frequency usage — estimated under $50/month for a cleared facility SOC.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # ── DIRECTION 2 ──────────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:rgba(52,211,153,0.06);border:1px solid rgba(52,211,153,0.25);
                border-radius:14px;padding:1.5rem 1.8rem;margin:1rem 0;">
        <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
            <div style="font-size:2.2rem">📡</div>
            <div>
                <div style="font-family:'Space Mono',monospace;font-size:1.05rem;font-weight:700;
                             color:#34d399;">Direction 2 — Automated STIX 2.1 Bundle Generation & TAXII Sharing</div>
                <div style="font-size:0.82rem;color:#64748b;margin-top:2px;">
                    Machine-Readable CTI · SIEM Integration · Cleared Facility Sharing
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col3, col4 = st.columns([3, 2])
    with col3:
        st.markdown("""
        <div class="info-box">
        <strong style="color:#34d399;">What It Is</strong><br><br>
        Every threat actor profile, diamond model campaign, KEV entry, and IOC on this platform
        would be automatically serialized into <strong>STIX 2.1 objects</strong> — the
        machine-readable standard for cyber threat intelligence — and made available via a
        <strong>TAXII 2.1 server endpoint</strong> that any SIEM or threat intelligence platform
        can query directly.<br><br>
        Threat actors become <code>threat-actor</code> objects. CVEs become
        <code>vulnerability</code> objects. Diamond model campaigns become
        <code>campaign</code> objects with linked <code>attack-pattern</code> and
        <code>indicator</code> objects. The entire platform's intelligence becomes
        machine-consumable without manual re-entry.
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown("""
        <div class="asset-box">
        <strong style="color:#34d399;">Why It Matters</strong><br><br>
        • Enables direct ingestion into Splunk, Microsoft Sentinel, and IBM QRadar<br><br>
        • Allows cleared facilities to share intelligence with each other via TAXII<br><br>
        • Eliminates manual re-entry of IOCs into SIEM platforms<br><br>
        • Aligns with EO 14028 requirements for machine-readable threat sharing<br><br>
        • Transforms the platform from a dashboard into a live data source for the SOC
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box" style="margin-top:0.5rem">
    <strong style="color:#34d399;">Implementation Path</strong><br><br>
    The Python <code>stix2</code> library would be used to serialize all platform data into
    STIX 2.1 bundles on demand. A lightweight Flask or FastAPI backend would expose a TAXII 2.1
    compliant REST endpoint — <code>/taxii2/collections/dib-cti/objects/</code> — that external
    SIEM connectors can poll on a configurable schedule. The Streamlit interface would add a
    one-click "Export as STIX Bundle" button on every threat actor profile and diamond model page,
    generating a downloadable <code>bundle.json</code>. Initial STIX generation for the current
    platform's dataset is estimated at under 200 objects — well within the performance envelope
    of the <code>stix2</code> library without a dedicated database backend.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # ── DIRECTION 3 ──────────────────────────────────────────────────────────
    st.markdown("""
    <div style="background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.25);
                border-radius:14px;padding:1.5rem 1.8rem;margin:1rem 0;">
        <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
            <div style="font-size:2.2rem">📦</div>
            <div>
                <div style="font-family:'Space Mono',monospace;font-size:1.05rem;font-weight:700;
                             color:#fbbf24;">Direction 3 — Expanded Data Integration for Broader Intelligence Coverage</div>
                <div style="font-size:0.82rem;color:#64748b;margin-top:2px;">
                    Data Expansion · API Integration · Statistical Grounding
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col5, col6 = st.columns([3, 2])
    with col5:
        st.markdown("""
        <div class="info-box">
        <strong style="color:#fbbf24;">What It Is</strong><br><br>
        The platform's current dataset is intentionally scoped — a subset of CISA KEV entries,
        four StopRansomware advisories, and CSIS incident records. While this produces
        high-precision intelligence, the limited sample size constrains the platform's ability
        to identify broader patterns, detect emerging vendor threats early, and support
        statistical analysis with confidence.<br><br>
        Expanding the data foundation means integrating the <strong>full CISA KEV catalog
        (~1,100+ entries)</strong> via the CISA KEV JSON API, the <strong>NVD CVE 2.0 API</strong>
        for full vendor CVE history going back to 2018, the <strong>complete CISA
        StopRansomware archive</strong> (50+ advisories), <strong>FBI IC3 Annual Reports
        (2019–2024)</strong> for longitudinal trend data, and
        <strong>DCSA Annual Threat Assessment reports</strong> for cleared contractor
        targeting patterns across multiple years.<br><br>
        Having constant framework publication, control, and vulnerability data directly integrated 
        into the platform enables stronger and more statistically grounded insights across every feature — 
        from risk scores to remediation recommendations — and 
        allows for longitudinal trend analysis that the current static dataset cannot support.
        </div>
        """, unsafe_allow_html=True)

    with col6:
        st.markdown("""
        <div class="threat-box" style="color:#ffffff">
        <strong style="color:#fbbf24;">Why It Matters</strong><br><br>
        • Threat model risk scores become statistically grounded rather than researcher-assigned<br><br>
        • ATT&CK heatmap intensities derived from actual incident frequency, not estimates<br><br>
        • Advisory tracker becomes comprehensive rather than illustrative<br><br>
        • Longitudinal data enables trend analysis — which vendors are getting worse over time<br><br>
        • Stronger dataset directly improves every existing feature on the platform
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box" style="margin-top:0.5rem">
    <strong style="color:#fbbf24;">Implementation Path</strong><br><br>
    The CISA KEV JSON feed (<code>https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json</code>)
    is publicly available and requires no authentication — a simple <code>requests.get()</code>
    call replaces the current static dataset and keeps the platform current automatically.
    The NVD CVE 2.0 API supports vendor-filtered queries with pagination, enabling a one-time
    historical pull and weekly delta updates. FBI IC3 reports and DCSA assessments are
    available as PDFs — a lightweight extraction pipeline using <code>pdfplumber</code> would
    parse key statistics into structured dataframes.<br><br>
    <strong style="color:#fbbf24;">Auto-Updating JSON Export:</strong> A scheduled background
    process — using Python's <code>schedule</code> library or a GitHub Actions cron job —
    would pull from all live feeds nightly, normalize the data into a unified schema, and
    write a versioned <code>dib_threat_intel.json</code> file that the Streamlit app loads
    at startup. This means every time the app is launched it automatically reflects the
    latest CISA advisories, KEV entries, and NVD CVEs without any manual intervention.
    The JSON file also serves as a portable, shareable intelligence snapshot that cleared
    facilities can ingest directly into their own tools — updated daily with zero analyst effort.<br><br>
    With a full dataset, the current researcher-assigned likelihood and impact scores in the
    threat model table can be replaced with frequency-derived scores, and the vendor heatmap
    can reflect confirmed incident counts rather than ordinal estimates — directly addressing
    the error sources identified in the Milestone 3 validation analysis.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # ── SUMMARY TABLE ────────────────────────────────────────────────────────
    st.markdown('<div class="sub-header">📋 Summary & Prioritization</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    These three directions build on each other sequentially — expanded data strengthens
    the existing features, STIX/TAXII makes the platform operationally shareable, and the
    AI attribution assistant puts finished intelligence directly in the hands of analysts.
    Together they move the DCTI platform from a milestone deliverable to a production-grade
    defense sector CTI operations tool.
    </div>
    """, unsafe_allow_html=True)

    import pandas as pd
    summary = pd.DataFrame({
        "Direction": [
            "AI Attribution Assistant",
            "STIX 2.1 / TAXII Sharing",
            "Expanded Data Integration",
        ],
        "Primary Benefit": [
            "Minutes-to-attribution vs. days",
            "Direct SIEM ingestion, no manual re-entry",
            "Statistically grounded scores and trends",
        ],
        "Key Technology": [
            "Claude / GPT-4 API + MITRE ATT&CK context",
            "stix2 Python library + TAXII 2.1 REST API",
            "CISA KEV API + NVD CVE 2.0 API + pdfplumber",
        ],
        "Milestone Connection": [
            "Extends threat actor profiles + ATT&CK heatmap",
            "Extends diamond models + KEV tracker",
            "Addresses Milestone 3 validation error sources",
        ],
        "Estimated Complexity": ["Medium", "Medium-High", "Low-Medium"],
    })
    st.dataframe(summary, use_container_width=True, hide_index=True)

    st.markdown("---")

    # ── SOURCES ───────────────────────────────────────────────────────────────
    st.markdown('<div class="sub-header">📚 Supporting References</div>', unsafe_allow_html=True)

    with st.expander("📄 View Sources & References", expanded=False):
        sources = [
            ("MITRE ATT&CK — STIX Representation of ATT&CK Data",
             "Documents how MITRE ATT&CK objects are represented in STIX 2.1, directly supporting Direction 2's STIX serialization approach.",
             "https://github.com/mitre/cti"),
            ("OASIS STIX 2.1 Specification",
             "The authoritative specification for STIX 2.1 object types used in Direction 2, including threat-actor, vulnerability, campaign, and indicator objects.",
             "https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html"),
            ("CISA — Known Exploited Vulnerabilities Catalog (KEV)",
             "Primary dataset for Direction 3 — KEV JSON feed is the live data source for the auto-updating pipeline.",
             "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
            ("Jacobs et al. — Exploit Prediction Scoring System (EPSS)",
             "Academic foundation supporting the expanded data direction — EPSS demonstrates that richer CVE datasets produce significantly better exploitation predictions.",
             "https://www.first.org/epss/"),
            ("Anthropic — Claude API Documentation",
             "Technical reference for Direction 1's LLM integration, including context window management for embedding threat actor profile data.",
             "https://docs.anthropic.com"),
            ("CISA — Emergency Directive BOD 22-01",
             "Policy basis for Direction 3 — BOD 22-01 mandates KEV-driven patching, making the auto-updating KEV JSON feed directly operationally relevant.",
             "https://www.cisa.gov/known-exploited-vulnerabilities"),
        ]

        for label, desc, url in sources:
            st.markdown(f"""
            <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                        border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                        padding:0.85rem 1.1rem;margin:0.5rem 0;">
                <div style="font-family:'Space Mono',monospace;font-size:0.8rem;
                            color:#38bdf8;margin-bottom:0.3rem;">📄 {label}</div>
                <div style="font-size:0.84rem;color:#ffffff;margin-bottom:0.4rem;">{desc}</div>
                <a href="{url}" target="_blank"
                   style="font-size:0.76rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
            </div>
            """, unsafe_allow_html=True)