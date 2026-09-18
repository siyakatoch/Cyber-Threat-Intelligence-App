import streamlit as st


# ── node content ────────────────────────────────────────────────────────────
MODEL1 = dict(
    title="LockBit 3.0 — Boeing Breach via Citrix Bleed (October 2023)",
    subtitle="Attributed: LockBit RaaS Affiliate  ·  Extortion  ·  Vendor CVE: CVE-2023-4966  ·  CISA Advisory AA23-325A",
    adv=[
        "LockBit 3.0 RaaS affiliate — Russia-nexus criminal ecosystem",
        "Operator: LockBit core group (~20% revenue cut)",
        "Aliases: LockBit Black · Buccaneer Spider",
        "Motive: Financial extortion via double extortion model",
    ],
    cap=[
        "CVE-2023-4966 (Citrix Bleed) — session token hijack, auth bypass",
        "No credentials needed — stolen session token grants full access",
        "Disabled Windows Defender before deploying LockBit 3.0 payload",
        "Exfiltrated ~43GB of Boeing data before encrypting systems",
        "Boeing refused ransom — data published on LockBit leak site",
        "T1190 · T1486 · T1048 · T1490 · T1562.001",
    ],
    inf=[
        "Type 1: LockBit Tor leak site — Boeing data published Nov 2023",
        "Type 2: Boeing's own Citrix NetScaler ADC portal (vendor product)",
        "Citrix Bleed exploited Boeing's remote access portal directly",
        "CISA KEV: CVE-2023-4966 added Oct 2023 — widely unpatched",
        "No custom C2 infrastructure needed — vendor portal was entry",
    ],
    vic=[
        "Boeing — major US defense prime (F/A-18, B-52, KC-46)",
        "Boeing Global Services — parts & distribution network",
        "~43GB stolen: supplier lists, distributor contacts, audits",
        "DFARS 252.204-7012: mandatory 72-hr DoD report triggered",
        "CMMC Gap: IR.2.093 · SI.2.214 · CA.2.158",
    ],
    meta=[
        ("Timestamp",
         "Oct 27 2023: LockBit claims breach · Nov 2 2023: Boeing data published after ransom refused · Nov 2023: CISA Advisory AA23-325A issued · CVE-2023-4966 added to KEV catalog Oct 2023"),
        ("Phase & Direction",
         "Extortion / Double extortion · External → Boeing Citrix portal (vendor product) → internal network · Supplier data exfiltrated before encryption · Vendor CVE was the sole entry vector — no separate exploit needed"),
        ("Result & Response",
         "~43GB Boeing data published publicly · CISA KEV mandate for CVE-2023-4966 patching across DIB · Boeing DFARS 72-hr DoD notification triggered · Emergency Citrix patch required across defense sector"),
    ],
)

MODEL2 = dict(
    title="APT29 — SolarWinds SUNBURST Supply Chain Compromise (2019–2020)",
    subtitle="Attributed: Russia SVR  ·  Espionage  ·  Vendor: SolarWinds Orion  ·  9 Federal Agencies + Defense Primes",
    adv=[
        "APT29 / Cozy Bear — Russia's SVR (Foreign Intelligence Service)",
        "Customer: Russian Federal Government",
        "Aliases: NOBELIUM · Midnight Blizzard · UNC2452 · Dark Halo",
        "Motive: Long-term espionage via trusted IT vendor access",
    ],
    cap=[
        "SUNBURST — backdoor trojanized into SolarWinds Orion DLL",
        "2-week dormancy post-install to defeat sandbox analysis",
        "Secondary payloads: TEARDROP · GoldMax · GoldFinder",
        "~18,000 orgs received update; ~100 actively exploited",
        "Valid Orion credentials used — no separate exploit needed",
        "T1195.002 · T1078 · T1027 · T1041 · T1078.004",
    ],
    inf=[
        "Type 1: Trojanized SolarWinds update server (vendor-owned)",
        "Actor C2 domains mimicking legitimate Orion telemetry",
        "Type 2: US Azure/AWS relay nodes — defeats geo-IP detection",
        "Pre-existing Orion firewall exceptions allowed C2 traffic",
        "Traffic indistinguishable from legitimate SolarWinds telemetry",
    ],
    vic=[
        "Defense primes using Orion: Booz Allen · SAIC · Leidos",
        "9 US federal agencies: Treasury · State · DHS · DOJ · CISA",
        "Assets: M365 email · classified networks · program data",
        "No binary integrity checks on vendor software updates",
        "CMMC Gap: SR.3.169 · CM.2.061 · FISMA: SA-12",
    ],
    meta=[
        ("Timestamp",
         "Oct 2019: SolarWinds build environment trojanized · Mar 2020: malicious Orion update deployed · Dec 13 2020: discovered by FireEye · Avg dwell time: 9–14 months undetected across all victims"),
        ("Phase & Direction",
         "Espionage / Intelligence collection · External → vendor software update → defense prime and federal agency networks · Supply chain pivot: attacking the vendor to reach hundreds of high-value targets simultaneously"),
        ("Result & Response",
         "Months of undetected access to federal email and classified networks · CISA Emergency Directive 21-01 · SEC lawsuit vs SolarWinds · Executive Order 14028 (software supply chain security) · SBOM requirements introduced"),
    ],
)


def build_svg(m):
    """Build a full-fit diamond SVG using absolute coordinates."""

    W = 1500
    NW = 420
    NH_ADV = 118
    NH_SIDE = 182
    NH_VIC  = 140
    FS_HEAD = 13
    FS_BODY = 13.5
    LH = 23

    cx = W // 2
    gap = (W - 3 * NW) // 3
    lx  = gap + NW // 2
    rx  = W - gap - NW // 2

    adv_top = 70
    side_top = adv_top + NH_ADV + 70
    vic_top  = side_top + NH_SIDE + 70
    total_h  = vic_top + NH_VIC + 50

    adv_x = cx - NW // 2
    cap_x = lx - NW // 2
    inf_x = rx - NW // 2

    adv_bot_y  = adv_top + NH_ADV
    side_mid_y = side_top + NH_SIDE // 2
    vic_top_y  = vic_top
    mid_y      = (adv_bot_y + vic_top_y) // 2

    def text_rows(lines, cx, y0, fs, fill, anchor="middle"):
        out = ""
        for i, ln in enumerate(lines):
            out += (f'<text x="{cx}" y="{y0 + i * LH}" '
                    f'text-anchor="{anchor}" font-size="{fs}" fill="{fill}" '
                    f'font-family="DM Sans, sans-serif">{ln}</text>\n')
        return out

    def node(x, y, w, h, rx_r, fill, stroke, title, lines, title_fill, body_fill):
        title_y = y + 18
        body_y0 = y + 36
        inner = (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx_r}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="0.8"/>\n')
        inner += (f'<text x="{x + w//2}" y="{title_y}" text-anchor="middle" '
                  f'font-size="{FS_HEAD}" font-weight="600" fill="{title_fill}" '
                  f'font-family="DM Sans, sans-serif">{title}</text>\n')
        inner += text_rows(lines, x + w // 2, body_y0, FS_BODY, body_fill)
        return inner

    def line(x1, y1, x2, y2, dash=False):
        style = 'stroke="rgba(148,163,184,0.35)" stroke-width="0.8"'
        if dash:
            style += ' stroke-dasharray="4 3"'
        return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" {style} fill="none"/>\n'

    def arrow(x1, y1, x2, y2):
        import math
        dx, dy_ = x2 - x1, y2 - y1
        length = math.sqrt(dx * dx + dy_ * dy_) or 1
        ux, uy = dx / length, dy_ / length
        ex, ey = x2 - ux * 6, y2 - uy * 6
        px, py = -uy * 5, ux * 5
        tip = f'{x2},{y2}'
        b1  = f'{ex + px},{ey + py}'
        b2  = f'{ex - px},{ey - py}'
        out = (f'<line x1="{x1}" y1="{y1}" x2="{ex}" y2="{ey}" '
               f'stroke="rgba(148,163,184,0.5)" stroke-width="0.8" fill="none"/>\n')
        out += (f'<polygon points="{tip} {b1} {b2}" '
                f'fill="rgba(148,163,184,0.5)"/>\n')
        return out

    svg = (f'<svg width="100%" viewBox="0 0 {W} {total_h}" '
           f'xmlns="http://www.w3.org/2000/svg">\n')

    svg += (f'<text x="{cx}" y="22" text-anchor="middle" font-size="15" '
            f'font-weight="600" fill="#7dd3fc" font-family="Space Mono, monospace">'
            f'{m["title"]}</text>\n')
    svg += (f'<text x="{cx}" y="42" text-anchor="middle" font-size="10" '
            f'fill="#475569" font-family="DM Sans, sans-serif">{m["subtitle"]}</text>\n')

    svg += line(cx, adv_bot_y, cx, mid_y, dash=True)
    svg += line(lx + NW // 2, side_mid_y, cx, mid_y, dash=True)
    svg += line(rx - NW // 2, side_mid_y, cx, mid_y, dash=True)
    svg += line(cx, mid_y, cx, vic_top_y, dash=True)

    svg += (f'<circle cx="{cx}" cy="{mid_y}" r="5" '
            f'fill="rgba(148,163,184,0.5)"/>\n')

    svg += arrow(cx, adv_bot_y, lx, side_top)
    svg += arrow(cx, adv_bot_y, rx, side_top)
    svg += arrow(lx, side_top + NH_SIDE, cx, vic_top_y)
    svg += arrow(rx, side_top + NH_SIDE, cx, vic_top_y)

    svg += node(adv_x, adv_top, NW, NH_ADV, 10,
                "rgba(216,90,48,0.15)", "#993c1d",
                "🔴  Adversary", m["adv"],
                "#f5c4b3", "#ffffff")

    svg += node(cap_x, side_top, NW, NH_SIDE, 10,
                "rgba(127,119,221,0.15)", "#534ab7",
                "⚡  Capability", m["cap"],
                "#cecbf6", "#ffffff")

    svg += node(inf_x, side_top, NW, NH_SIDE, 10,
                "rgba(29,158,117,0.15)", "#0f6e56",
                "🌐  Infrastructure", m["inf"],
                "#9fe1cb", "#ffffff")

    vic_x = cx - NW // 2
    svg += node(vic_x, vic_top, NW, NH_VIC, 10,
                "rgba(186,117,23,0.15)", "#854f0b",
                "🎯  Victim", m["vic"],
                "#fac775", "#ffffff")

    svg += "</svg>"
    return svg


def render_meta(meta):
    cols = st.columns(3)
    for col, (label, text) in zip(cols, meta):
        with col:
            st.markdown(f"""
            <div class="info-box">
                <strong>{label}</strong><br><br>
                <span style="font-size:0.85rem">{text}</span>
            </div>""", unsafe_allow_html=True)


def render():
    st.markdown('<div class="section-header">💎 Diamond Models — Defense Vendor Ecosystem</div>',
                unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    The <strong>Diamond Model of Intrusion Analysis</strong> structures adversary campaigns across four nodes:
    <strong>Adversary</strong> (who), <strong>Capability</strong> (how),
    <strong>Infrastructure</strong> (where), and <strong>Victim</strong> (target).
    Both models represent real, documented cases where adversaries exploited
    <strong>trusted vendor products</strong> to gain access to defense contractors —
    the defining attack pattern of the modern DIB threat landscape.
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs([
        "💎 Model 1 — LockBit 3.0: Boeing via Citrix Bleed (2023)",
        "💎 Model 2 — APT29: SolarWinds Supply Chain (2019–2020)",
    ])

    with tab1:
        st.markdown(build_svg(MODEL1), unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">🔗 Meta-Features</div>', unsafe_allow_html=True)
        render_meta(MODEL1["meta"])

    with tab2:
        st.markdown(build_svg(MODEL2), unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">🔗 Meta-Features</div>', unsafe_allow_html=True)
        render_meta(MODEL2["meta"])

    st.markdown("---")

    # ── Sources (expandable) ──────────────────────────────────────────────────
    with st.expander("📚 Sources & References", expanded=False):
        sources = [
            {
                "label": "CISA StopRansomware — LockBit 3.0 Advisory AA23-325A (Nov 2023)",
                "desc": "Joint CISA/FBI/MS-ISAC advisory on LockBit 3.0 including Citrix Bleed (CVE-2023-4966) exploitation, TTPs, and indicators of compromise. Primary source for Model 1 capability and infrastructure nodes.",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a",
                "apa": "CISA, FBI, & MS-ISAC. (2023, November). <em>LockBit 3.0 ransomware affiliates exploit CVE 2023-4966 Citrix Bleed vulnerability.</em> CISA Advisory AA23-325A.",
            },
            {
                "label": "CISA KEV — CVE-2023-4966 Citrix Bleed",
                "desc": "CISA Known Exploited Vulnerabilities catalog entry for CVE-2023-4966 (Citrix Bleed). Mandates patching across federal and DIB environments under BOD 22-01. Used in Model 1 infrastructure node.",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "apa": "Cybersecurity and Infrastructure Security Agency. (2023). <em>Known exploited vulnerabilities catalog: CVE-2023-4966.</em> CISA.",
            },
            {
                "label": "DFARS 252.204-7012 — Safeguarding Covered Defense Information",
                "desc": "DFARS clause requiring 72-hour DoD cyber incident reporting for defense contractors. Basis for the Boeing mandatory reporting obligation referenced in Model 1 victim node.",
                "url": "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting.",
                "apa": "Department of Defense. (2023). <em>DFARS 252.204-7012: Safeguarding covered defense information and cyber incident reporting.</em> acquisition.gov.",
            },
            {
                "label": "FireEye / Mandiant — SUNBURST Backdoor Analysis (Dec 2020)",
                "desc": "Original public disclosure of the SolarWinds SUNBURST supply chain attack including technical analysis of the trojanized Orion DLL, C2 communication patterns, and 2-week dormancy mechanism. Primary source for Model 2.",
                "url": "https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor",
                "apa": "FireEye. (2020, December 13). <em>Highly evasive attacker leverages SolarWinds supply chain to compromise multiple global victims with SUNBURST backdoor.</em> Mandiant.",
            },
            {
                "label": "MITRE ATT&CK — APT29 (G0016) Group Profile",
                "desc": "MITRE ATT&CK group profile for APT29 including all aliases, TTP mappings, and SolarWinds campaign attribution. Source for technique IDs and capability node in Model 2.",
                "url": "https://attack.mitre.org/groups/G0016/",
                "apa": "MITRE Corporation. (2025). <em>ATT&CK Groups: APT29 (G0016).</em> MITRE ATT&CK. https://attack.mitre.org/groups/G0016/",
            },
            {
                "label": "CISA — Joint Advisory AA24-038A: Volt Typhoon / Supply Chain Context",
                "desc": "Provides broader context on vendor and supply chain targeting of US defense infrastructure, supporting the supply chain risk framing across both diamond models.",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a",
                "apa": "CISA, NSA, & FBI. (2024, February 7). <em>PRC state-sponsored actors compromise and maintain persistent access to U.S. critical infrastructure.</em> CISA Advisory AA24-038A.",
            },
            {
                "label": "CSIS — Significant Cyber Incidents (2022–Dec 2025)",
                "desc": "Timeline of significant cyber attacks on defense organizations. Source for Boeing/LockBit October 2023 incident context and SolarWinds defense prime victim confirmation.",
                "url": "https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents",
                "apa": "Center for Strategic and International Studies. (2025). <em>Significant cyber incidents.</em> CSIS.",
            },
            {
                "label": "DNI — 2026 Annual Threat Assessment",
                "desc": "Confirms Russia and China as the most persistent cyber threats against US defense infrastructure. Supports adversary attribution in both diamond models.",
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