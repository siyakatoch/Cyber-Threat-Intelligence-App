import streamlit as st
import pages.background as pg1
import pages.stakeholders as pg2
import pages.cti_use_case as pg3
import pages.threat_trends as pg4
import pages.diamond_models as pg5
import pages.cti_dashboard as pg6
import pages.intelligence_buy_in as pg7
import pages.cti_sourcing as pg8
import pages.ethics_security as pg9
import pages.about_us as pg10
import pages.analysis as pg11
import pages.ransomware_analysis as pg12
import pages.operational_intel as pg13
import pages.triage_dashboard as pg14
import pages.future_cti as pg15
import pages.key_insights as pg16

import base64
import os

def get_image_base64(image_path):
    """Load a local image and convert to base64 for embedding in HTML."""
    try:
        with open(image_path, "rb") as f:
            data = base64.b64encode(f.read()).decode("utf-8")
        ext = os.path.splitext(image_path)[1].lower().replace(".", "")
        if ext == "jpg":
            ext = "jpeg"
        return f"data:image/{ext};base64,{data}"
    except FileNotFoundError:
        return ""

# ── Page config ──
st.set_page_config(
    page_title="CTI - Defense Contractor Vendors",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Session state for page navigation ──
if "page" not in st.session_state:
    st.session_state.page = "Homepage"

# ── Custom CSS ──
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'DM Sans', sans-serif;
        font-size: 16px;
        color: #ffffff
    }

    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #0d1b2a 50%, #0a1628 100%);
        color: #ffffff;
        background-image:
            radial-gradient(circle, rgba(56,189,248,0.16) 1px, transparent 1px),
            radial-gradient(circle, rgba(56,189,248,0.07) 1px, transparent 1px);
        background-size: 38px 38px, 19px 19px;
        background-position: 0 0, 9px 9px;
    }

    /* Remove top padding */
    .stApp > div:first-child { padding-top: 0 !important; }
    .block-container { padding-top: 0 !important; margin-top: 0 !important; padding-bottom: 0 !important; }
    header[data-testid="stHeader"] { display: none !important; }
    [data-testid="collapsedControl"] { display: none; }
    [data-testid="stSidebar"] { display: none; }

    /* ── Navbar ── */
    .topnav-wrapper {
        # background: linear-gradient(90deg, #060d18 0%, #0d1f36 60%, #0a1a30 100%);
        border-bottom: 2px solid #1e4976;
        # box-shadow: 0 4px 32px rgba(14, 165, 233, 0.12);
        padding: 0.6rem 2rem;
        margin-left: -4rem;
        margin-right: -4rem;
        margin-top: -1rem;
        margin-bottom: 0;
    }
    .topnav-inner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        max-width: 1400px;
        margin: 0 auto;
        gap: 1rem;
    }
    .topnav-brand-col { display: flex; flex-direction: column; }
    .topnav-abrv {
        font-family: 'Space Mono', monospace;
        font-size: 1.7rem;
        color: #38bdf8;
        font-weight: 700;
        letter-spacing: 2px;
        line-height: 1;
    }
    .topnav-sub {
        font-size: 0.62rem;
        color: #475569;
        margin-top: 0.1rem;
        text-wrap: nowrap;
    }


    /* Horizontal nav links */
    .topnav-links {
        display: flex;
        align-items: center;
        gap: 0.1rem;
        flex-wrap: nowrap;
    }
    .topnav-links a {
        font-family: 'DM Sans', sans-serif;
        font-size: 0.78rem;
        color: #7dd3fc;
        text-decoration: none;
        padding: 0.3rem 0.65rem;
        border-radius: 6px;
        white-space: nowrap;
        transition: background 0.15s, color 0.15s;
        letter-spacing: 0.01em;
    }
    .topnav-links a:hover { background: rgba(56,189,248,0.12); color: #e0f2fe; }
    .topnav-links a.active {
        background: rgba(56,189,248,0.18);
        color: #38bdf8;
        font-weight: 600;
    }
    .topnav-sep {
        color: #1e4976;
        font-size: 0.9rem;
        user-select: none;
    }

    /* ── Hero section ── */
    .hero-section {
        text-align: center;
        padding: 0;
        margin-left: -4rem;
        margin-right: -4rem;
        margin-top: -1rem;
        height: 93vh;
        position: relative;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        overflow: hidden;
    }
    .hero-bg {
        position: absolute;
        inset: 0;
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        opacity: 0.35;
    }
    .hero-overlay {
        position: absolute;
        inset: 0;
        background: rgba(6, 13, 24, 0.55);
    }
    .hero-content {
        position: relative;
        z-index: 2;
        padding: 2rem 3rem;
    }
    .hero-title {
        font-family: 'Space Mono', monospace;
        font-size: clamp(3.5rem, 8vw, 6.5rem);
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 4px;
        line-height: 1;
        margin-bottom: 0.5rem;
        text-shadow: 0 0 60px rgba(56,189,248,0.35), 0 0 120px rgba(14,165,233,0.15);
    }
    .hero-subtitle {
        font-family: 'DM Sans', sans-serif;
        font-size: clamp(1rem, 2.5vw, 1.5rem);
        color: #e2e8f0;
        font-weight: 300;
        letter-spacing: 0.05em;
        margin-bottom: 0.4rem;
    }
    .hero-meta {
        font-size: 0.82rem;
        color: #475569;
        letter-spacing: 0.1em;
        margin-bottom: 3rem;
    }

    /* ── Nav cards (homepage grid) ── */
    .nav-cards-grid {
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 1rem;
        max-width: 1100px;
        margin: 0 auto;
        padding-bottom: 3rem;
    }
    .nav-card {
        background: rgba(14, 39, 68, 0.7);
        border: 1px solid #1e4976;
        border-radius: 14px;
        padding: 1.4rem 1.2rem;
        width: 180px;
        text-align: center;
        cursor: pointer;
        transition: border-color 0.2s, box-shadow 0.2s, transform 0.15s;
        text-decoration: none;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.6rem;
    }
    .nav-card:hover {
        border-color: #38bdf8;
        box-shadow: 0 0 24px rgba(56,189,248,0.18);
        transform: translateY(-3px);
    }
    .nav-card-icon { font-size: 2rem; line-height: 1; }
    .nav-card-label {
        font-family: 'DM Sans', sans-serif;
        font-size: 0.82rem;
        color: #cbd5e1;
        font-weight: 500;
        line-height: 1.35;
    }

    /* Other styles carried over */
    .section-header {
        font-family: 'Space Mono', monospace;
        font-size: 1.6rem;
        font-weight: 700;
        color: #38bdf8;
        border-left: 4px solid #0ea5e9;
        padding-left: 1rem;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-family: 'Space Mono', monospace;
        font-size: 1rem;
        font-weight: 700;
        color: #38bdf8;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 0.4rem;
    }
    .kpi-card {
        background: linear-gradient(135deg, #0f2744 0%, #1a3a5c 100%);
        border: 1px solid #1e4976;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(14,165,233,0.1);
    }
    .kpi-value { font-family: 'Space Mono', monospace; font-size: 2rem; font-weight: 700; color: #38bdf8; }
    .kpi-label { font-size: 0.78rem; color: #ffffff; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 0.25rem; }
    .kpi-delta { font-size: 0.82rem; color: #ffffff; margin-top: 0.2rem; }
    .kpi-delta-good { font-size: 0.82rem; color: #34d399; margin-top: 0.2rem; }
    .info-box {
        background: rgba(14,165,233,0.07);
        border: 1px solid rgba(56,189,248,0.25);
        border-radius: 10px;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        font-size: 0.92rem;
        line-height: 1.6;
        color: #ffffff;
    }
    .threat-box {
        background: rgba(239,68,68,0.07);
        border: 1px solid rgba(239,68,68,0.3);
        border-radius: 10px;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        font-size: 0.92rem;
        color: #ffffff;
    }
    .asset-box {
        background: rgba(52,211,153,0.07);
        border: 1px solid rgba(52,211,153,0.3);
        border-radius: 10px;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        font-size: 0.92rem;
        color: #ffffff;
    }
    .badge {
        display: inline-block;
        background: rgba(56,189,248,0.15);
        border: 1px solid rgba(56,189,248,0.4);
        color: #ffffff;
        border-radius: 999px;
        padding: 0.15rem 0.7rem;
        font-size: 0.75rem;
        margin: 0.15rem;
        font-family: 'Space Mono', monospace;
    }
    .badge-red { background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.4); color: #ffffff; }
    .badge-green { background: rgba(52,211,153,0.15); border: 1px solid rgba(52,211,153,0.4); color: #ffffff; }
    .badge-yellow { background: rgba(251,191,36,0.15); border: 1px solid rgba(251,191,36,0.4); color: #ffffff; }
    hr { border-color: #1e3a5f; }
    label { color: #ffffff !important; }

    /* Streamlit button override for nav cards */
    div[data-testid="stButton"] > button {
        background: rgba(14, 39, 68, 0.7) !important;
        border: 1px solid #1e4976 !important;
        border-radius: 14px !important;
        color: #cbd5e1 !important;
        padding: 1.4rem 1.2rem !important;
        width: 180px !important;
        height: 110px !important;
        font-family: 'DM Sans', sans-serif !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
        line-height: 1.35 !important;
        transition: all 0.2s !important;
        white-space: pre-wrap !important;
    }
    div[data-testid="stButton"] > button:hover {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 24px rgba(56,189,248,0.18) !important;
        transform: translateY(-3px) !important;
        color: #e0f2fe !important;
    }
</style>
""", unsafe_allow_html=True)

# ── Page definitions ──
NAV_PAGES = [
    ("Homepage",                        None,   None),
    ("Introduction",                    "📋",   "Introduction & Background"),
    ("Stakeholders",                    "👥",   "Stakeholders & User Stories"),
    ("Threat Model",                    "🎯",   "CTI Use Case / Threat Model"),
    ("Trends & Assets",                 "⚠️",   "Threat Trends & Critical Assets"),
    ("Diamond Models",                  "💎",   "Diamond Models"),
    ("Dashboard",                       "📊",   "CTI Dashboard"),
    ("Triage Dashboard",                "🏩",   "Triage Dashboard"),
    ("Intelligence Buy-in",             "📄",   "Intelligence Buy-In"),
    ("Linear Regression Analysis",      "📈",   "Linear Regression Analysis"),
    ("Ransomeware Prediction",          "🤖",   "Ransomeware Prediction"),
    ("Intelligence & Dissemination",    "📢",   "Intelligence & Dissemination"),
    ("CTI Sourcing",                    "🔍",   "CTI Sourcing"),
    ("Ethics & Security Practices",     "🔒",   "Ethics & Security Practices"),
    ("Key Insights",                    "🔑",   "Key Insights"),
    ("Future CTI Directions",           "⏳",   "Future CTI Directions"),
    ("About Us & Checklist",            "🫆",   "About Us & Checklist")
]

current = st.session_state.page

# ── Top Navbar ──
st.markdown('<div class="topnav-wrapper"><div class="topnav-inner">', unsafe_allow_html=True)

brand_col, nav_col = st.columns([2, 7])

with brand_col:
    st.markdown("""
    <div class="topnav-brand-col">
        <div class="topnav-abrv">CTI</div>
        <div class="topnav-sub">Vulnerabilities in Defense Contract Vendors · 2026</div>
    </div>
    """, unsafe_allow_html=True)

with nav_col:
    nav_items = [p for p in NAV_PAGES if p[0] != "Homepage"]

    if current == "Homepage":
        # ── Full horizontal link buttons on homepage ──
        cols = st.columns(len(nav_items) + 1)
        with cols[0]:
            if st.button("Home", key="nav_home"):
                st.session_state.page = "Homepage"
                st.rerun()
        for i, (label, icon, _) in enumerate(nav_items, start=1):
            with cols[i]:
                if st.button(label, key=f"nav_{label}"):
                    st.session_state.page = label
                    st.rerun()
    else:
        # ── Dropdown on section pages ──
        page_labels = ["Homepage"] + [p[0] for p in nav_items]
        current_index = page_labels.index(current) if current in page_labels else 0
        _, dd_col = st.columns([3, 1])   # push to right side
        with dd_col:
            selected = st.selectbox(
                "Navigate to section:",
                page_labels,
                index=current_index,
                label_visibility="collapsed",
                key="nav_dropdown"
            )
        if selected != current:
            st.session_state.page = selected
            st.rerun()

st.markdown('</div></div>', unsafe_allow_html=True)

# Override nav button styling to look like links (homepage only)
st.markdown("""
<style>
div[data-testid="stHorizontalBlock"] div[data-testid="stButton"] > button {
    background: transparent !important;
    border: none !important;
    border-radius: 6px !important;
    color: #ffffff !important;
    padding: 0.3rem 0.65rem !important;
    width: auto !important;
    height: auto !important;
    font-size: 0.78rem !important;
    font-weight: 500 !important;
    white-space: nowrap !important;
    min-height: 0 !important;
}
div[data-testid="stHorizontalBlock"] div[data-testid="stButton"] > button:hover {
    background: rgba(56,189,248,0.12) !important;
    color: #e0f2fe !important;
    transform: none !important;
    box-shadow: none !important;
}
</style>
""", unsafe_allow_html=True)

# ── Page Rendering ──
current = st.session_state.page

if current == "Homepage":
    # Hero - load image as base64
    img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "hero.jpg")
    img_b64 = get_image_base64(img_path)
    hero_bg_style = f"background-image: url('{img_b64}');" if img_b64 else "background: #0a0e1a;"

    circle_pages = [(label, icon, full) for label, icon, full in NAV_PAGES if label != "Homepage"]

    # Inject hidden Streamlit buttons that JS will click programmatically
    btn_cols = st.columns(len(circle_pages))
    for i, (label, icon, full) in enumerate(circle_pages):
        with btn_cols[i]:
            if st.button(label, key=f"circle_btn_{label}"):
                st.session_state.page = label
                st.rerun()

    # Hide those buttons visually — JS will trigger them
    st.markdown("""
    <style>
    div[data-testid="stHorizontalBlock"]:first-of-type
        div[data-testid="stButton"] > button {
        display: none !important;
    }
    </style>
    """, unsafe_allow_html=True)

    import json
    cards = [{"label": label, "icon": icon} for label, icon, full in circle_pages]
    cards_by_label = {c["label"]: c["icon"] for c in cards}

    row1 = ["Introduction", "Stakeholders", "Threat Model", "Trends & Assets"]
    row2 = ["Diamond Models", "Dashboard", "Triage Dashboard", "Intelligence Buy-in", "Linear Regression Analysis", "Ransomeware Prediction"]
    row3 = ["Intelligence & Dissemination", "CTI Sourcing", "Ethics & Security Practices", "Key Insights", "Future CTI Directions", "About Us & Checklist"]

    st.components.v1.html(f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600&display=swap');
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    html, body {{ width:100%; height:100%; background:transparent; }}

    @keyframes blink {{ 0%,100%{{opacity:1}} 50%{{opacity:0}} }}
    .cursor {{
        display:inline-block; width:7px; height:12px;
        vertical-align:middle; margin-left:2px;
        animation:blink 1s step-end infinite;
    }}

    .scene {{
        width:100%; min-height:100%;
        display:flex; flex-direction:column; align-items:center;
        padding: 27.5px 25px 22.5px;
        background:radial-gradient(ellipse at center, rgba(56,189,248,0.18) 0%, rgba(4,165,233,0) 55%);
        background-image: radial-gradient(ellipse at center, rgba(56,189,248,0.18) 0%, rgba(4,165,233,0) 55%),
            radial-gradient(circle, rgba(56,189,248,0.1) 1px, transparent 1px);
        background-size: 100% 100%, 32px 32px;
    }}

    .hero {{ text-align:center; margin-bottom:14px; }}
    .hero-title {{
        font-family:'Space Mono',monospace;
        font-size: clamp(2.5rem, 6.25vw, 4.375rem);
        font-weight:700; color:#38bdf8; letter-spacing:6px; line-height:1;
        text-shadow:0 0 40px rgba(56,189,248,0.4);
    }}
    .hero-sub {{
        font-family:'DM Sans',sans-serif;
        font-size: clamp(1.125rem, 2.5vw, 1.5rem);
        font-weight:700; color:#ffffff; margin-top:8px;
    }}
    .hero-meta {{
        font-family:'DM Sans',sans-serif; font-size:0.94rem;
        font-weight:600; color:#7dd3fc; letter-spacing:0.1em; margin-top:4px;
    }}

    .rows-wrap {{ display:flex; flex-direction:column; gap: 15px; width:100%; max-width:920px; }}

    .sec-banner {{
        border-radius:8px 8px 0 0; padding:7px 14px;
        display:flex; align-items:center; gap:10px;
    }}
    .sec-dot {{
        width:8px; height:8px; border-radius:50%; flex-shrink:0;
        animation:pulse-dot 2s ease-in-out infinite;
    }}
    @keyframes pulse-dot {{
        0%, 100% {{ transform:scale(1); opacity:1; }}
        50% {{ transform:scale(1.4); opacity:0.7; }}
    }}
    .sec-title {{
        font-family:'Space Mono',monospace; font-size:13.75px;
        font-weight:700; letter-spacing:0.2em;
    }}
    .sec-comment {{
        font-family:'Space Mono',monospace; font-size:11.875px; opacity:0.5;
    }}

    .sec-body {{
        border-radius:0 0 10px 10px; padding:12.5px 12.5px;
        display:flex; gap:17.4px; justify-content:space-between;                 
    }}

    .nav-card {{
        display:flex; flex-direction:column; align-items:center; gap:5px;
        cursor:pointer; border-radius:10px; padding: 13.75px 7.5px 11.25px;
        flex:1;
        transition:transform 0.15s, box-shadow 0.15s;
    }}
    .nav-card:hover {{ transform:translateY(-4px); }}
    .card-icon {{ font-size:1.69rem; line-height:1; }}
    .card-label {{
        font-family:'DM Sans',sans-serif; font-size:12.5px;
        font-weight:600; color:#ffffff; text-align:center; line-height:1.3;
    }}

    /* Blue — Intelligence */
    .row-blue .sec-banner {{
        background:rgba(56,189,248,0.15); border:1px solid rgba(56,189,248,0.35); border-bottom:none;
    }}
    .row-blue .sec-dot {{ background:#38bdf8; box-shadow:0 0 8px #38bdf8; }}
    .row-blue .sec-title {{ color:#38bdf8; }}
    .row-blue .sec-comment {{ color:#38bdf8; }}
    .row-blue .cursor {{ background:#38bdf8; }}
    .row-blue .sec-body {{
        background:rgba(56,189,248,0.05); border:1px solid rgba(56,189,248,0.2); border-top:none;
    }}
    .row-blue .nav-card {{
        background:rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.2);
    }}
    .row-blue .nav-card:hover {{ box-shadow:0 0 18px rgba(56,189,248,0.3); border-color:#38bdf8; }}

    /* Green — Analysis */
    .row-green .sec-banner {{
        background:rgba(52,211,153,0.15); border:1px solid rgba(52,211,153,0.35); border-bottom:none;
    }}
    .row-green .sec-dot {{ background:#34d399; box-shadow:0 0 8px #34d399; }}
    .row-green .sec-title {{ color:#34d399; }}
    .row-green .sec-comment {{ color:#34d399; }}
    .row-green .cursor {{ background:#34d399; }}
    .row-green .sec-body {{
        background:rgba(52,211,153,0.05); border:1px solid rgba(52,211,153,0.2); border-top:none;
    }}
    .row-green .nav-card {{
        background:rgba(52,211,153,0.08); border:1px solid rgba(52,211,153,0.2);
    }}
    .row-green .nav-card:hover {{ box-shadow:0 0 18px rgba(52,211,153,0.3); border-color:#34d399; }}

    /* Purple — Platform */
    .row-purple .sec-banner {{
        background:rgba(168,85,247,0.15); border:1px solid rgba(168,85,247,0.35); border-bottom:none;
    }}
    .row-purple .sec-dot {{ background:#a855f7; box-shadow:0 0 8px #a855f7; }}
    .row-purple .sec-title {{ color:#a855f7; }}
    .row-purple .sec-comment {{ color:#a855f7; }}
    .row-purple .cursor {{ background:#a855f7; }}
    .row-purple .sec-body {{
        background:rgba(168,85,247,0.05); border:1px solid rgba(168,85,247,0.2); border-top:none;
    }}
    .row-purple .nav-card {{
        background:rgba(168,85,247,0.08); border:1px solid rgba(168,85,247,0.2);
    }}
    .row-purple .nav-card:hover {{ box-shadow:0 0 18px rgba(168,85,247,0.3); border-color:#a855f7; }}
    </style>
    </head>
    <body>
    <div class="scene">
        <div class="hero">
            <div class="hero-title">CTI</div>
            <div class="hero-sub">Vulnerabilities in Defense Contract Vendors</div>
            <div class="hero-meta">Cyber Threat Intelligence Platform &nbsp;&middot;&nbsp; Defense Sector &nbsp;&middot;&nbsp; 2026</div>
        </div>
        <div class="rows-wrap">
            <div class="row-blue">
                <div class="sec-banner">
                    <div class="sec-dot"></div>
                    <div class="sec-title">&gt; INTELLIGENCE</div>
                    <div class="sec-comment">// threat actors &middot; use cases &middot; trends<span class="cursor"></span></div>
                </div>
                <div class="sec-body" id="row1"></div>
            </div>
            <div class="row-green">
                <div class="sec-banner">
                    <div class="sec-dot"></div>
                    <div class="sec-title">&gt; ANALYSIS</div>
                    <div class="sec-comment">// models &middot; dashboards &middot; predictions<span class="cursor"></span></div>
                </div>
                <div class="sec-body" id="row2"></div>
            </div>
            <div class="row-purple">
                <div class="sec-banner">
                    <div class="sec-dot"></div>
                    <div class="sec-title">&gt; PLATFORM</div>
                    <div class="sec-comment">// ethics &middot; sourcing &middot; future directions<span class="cursor"></span></div>
                </div>
                <div class="sec-body" id="row3"></div>
            </div>
        </div>
    </div>
    <script>
    const row1Pages = {json.dumps(row1)};
    const row2Pages = {json.dumps(row2)};
    const row3Pages = {json.dumps(row3)};
    const iconMap   = {json.dumps(cards_by_label)};

    function makeCard(label) {{
        const icon = iconMap[label] || "📄";
        const card = document.createElement("div");
        card.className = "nav-card";
        card.innerHTML = `<div class="card-icon">${{icon}}</div><div class="card-label">${{label}}</div>`;
        card.addEventListener("click", () => {{
            const btns = window.parent.document.querySelectorAll("button");
            for (const btn of btns) {{
                if (btn.innerText.trim() === label) {{ btn.click(); break; }}
            }}
        }});
        return card;
    }}

    function buildRow(rowId, pages) {{
        const container = document.getElementById(rowId);
        pages.forEach(label => container.appendChild(makeCard(label)));
    }}

    buildRow("row1", row1Pages);
    buildRow("row2", row2Pages);
    buildRow("row3", row3Pages);
    </script>
    </body>
    </html>
    """, height=750, scrolling=False) 

elif current == "Introduction":
    pg1.render()
elif current == "Stakeholders":
    pg2.render()
elif current == "Threat Model":
    pg3.render()
elif current == "Trends & Assets":
    pg4.render()
elif current == "Diamond Models":
    pg5.render()
elif current == "Dashboard":
    pg6.render()
elif current == "Intelligence Buy-in":
    pg7.render()
elif current == "Linear Regression Analysis":
    pg11.render()
elif current == "Ethics & Security Practices":
    pg9.render()
elif current == "CTI Sourcing":
    pg8.render()
elif current == "Ransomeware Prediction":
    pg12.render()
elif current == "About Us & Checklist":
    pg10.render()
elif current == "Intelligence & Dissemination":
    pg13.render()
elif current == "Triage Dashboard":
    pg14.render()
elif current == "Future CTI Directions":
    pg15.render()
elif current == "Key Insights":
    pg16.render()