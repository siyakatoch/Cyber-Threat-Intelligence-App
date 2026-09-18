import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")
from datetime import datetime


# ── Load & Clean Data ─────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    kev = pd.read_json("Defense_KEV_Entries.json")
    cvss = pd.read_json("Data_with_Scores.json")

    for col in ["Base", "Impact", "Exploitability"]:
        cvss[col] = cvss[col].apply(
            lambda x: float(str(x).replace("~", "").strip())
            if str(x).replace("~", "").replace(".", "").isdigit()
            or (str(x).replace("~", "").replace(".", "").lstrip("-").isdigit())
            else np.nan
        )

    kev["Date Added"]  = pd.to_datetime(kev["Date Added"])
    kev["Due Date"]    = pd.to_datetime(kev["Due Date"])
    kev["Year"]        = kev["Date Added"].dt.year
    kev["Days Window"] = (kev["Due Date"] - kev["Date Added"]).dt.days

    merged = kev.merge(
        cvss[["CVE ID", "Base", "Impact", "Exploitability"]],
        on="CVE ID", how="left"
    )
    return kev, cvss, merged


def render():
    kev_df, cvss_df, merged_df = load_data()

    # ── CSS ───────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    .ops-card {
        background: rgba(14,165,233,0.06);
        border: 1px solid rgba(56,189,248,0.18);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
        color: #ffffff;
    }
    .coa-box {
        background: rgba(34,197,94,0.05);
        border: 1px solid rgba(34,197,94,0.2);
        border-left: 4px solid #22c55e;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
    }
    .warn-box {
        background: rgba(239,68,68,0.05);
        border: 1px solid rgba(239,68,68,0.2);
        border-left: 4px solid #ef4444;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
    }
    .dissem-box {
        background: rgba(168,85,247,0.05);
        border: 1px solid rgba(168,85,247,0.2);
        border-left: 4px solid #a855f7;
        border-radius: 0 10px 10px 0;
        padding: 1rem 1.2rem;
        margin: 0.6rem 0;
        color: #ffffff;
        font-size: 0.87rem;
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

    # ── Helpers ───────────────────────────────────────────────────────────

    def chart_header(title, tooltip, key=None):
        st.markdown(f"""
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                <div class="sub-header">{title}</div>
                <div class="tooltip-icon">ⓘ<span class="tooltip-text">{tooltip}</span></div>
            </div>
        """, unsafe_allow_html=True)  

    # ── Page Header ───────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🛡️ Operational Intelligence & Dissemination</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="ops-card">
    This page translates raw CISA KEV and CVSS data into <strong>actionable operational intelligence</strong>
    for defense contractors like Lockheed Martin, Boeing, and Leidos. It covers two core areas:<br><br>
    📋 <strong>Courses of Action</strong> — specific recommended responses for each stakeholder<br>
    📡 <strong>Dissemination Strategy</strong> — who gets what intelligence, when, and how
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs([
        "📋 Courses of Action",
        "📡 Dissemination Strategy",
    ])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — COURSES OF ACTION
    # ════════════════════════════════════════════════════════════════════════
    with tab1:
        st.markdown('<div class="sub-header">Recommended responses based on intelligence findings</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="ops-card">
        Courses of Action (COAs) translate intelligence findings into specific, actionable steps for
        each stakeholder. Each COA is tied directly to a real finding from our CISA KEV and CVSS
        data and maps to a concrete operational response for defense contractors.
        </div>
        """, unsafe_allow_html=True)

        coa_data = [
            {"ID": "COA-001", "Priority": "🔴 Critical", "Stakeholder": "IT / Network Teams", "Vendor": "Cisco",
             "Finding": "Vendor Concentration Risk",
             "Action": "Immediately audit all Cisco ASA and IOS XE devices for CVE-2023-20198 and CVE-2023-20269. Prioritize internet-facing devices. Apply patches within CISA BOD 22-01 deadline.",
             "Timeline": "≤7 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-002", "Priority": "🔴 Critical", "Stakeholder": "IT / Network Teams", "Vendor": "Microsoft",
             "Finding": "Ransomware Active Exploitation",
             "Action": "Enforce MFA on all Microsoft Active Directory accounts. Audit AD for Kerberoastable service accounts. Review privileged access against CVE-2022-26923 exposure.",
             "Timeline": "≤14 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-003", "Priority": "🔴 Critical", "Stakeholder": "SOC Analysts", "Vendor": "Microsoft",
             "Finding": "Ransomware Active Exploitation",
             "Action": "Deploy detection rules for Kerberoasting activity and NTLM relay attacks. Monitor for unusual AD authentication patterns. Alert on CVE-2023-23397 exploitation indicators.",
             "Timeline": "≤7 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-004", "Priority": "🟠 High", "Stakeholder": "IT / Network Teams", "Vendor": "Google",
             "Finding": "Vendor Concentration Risk",
             "Action": "Enforce Chrome enterprise auto-update policy across all endpoints. Verify Chrome version compliance via SCCM or Intune. Restrict WebGPU where not operationally required.",
             "Timeline": "≤14 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-005", "Priority": "🟠 High", "Stakeholder": "CISOs & Leadership", "Vendor": "All Vendors",
             "Finding": "Tight Patch Windows",
             "Action": "Establish a formal patch SLA policy aligned to CISA BOD 22-01 deadlines. Present breach cost data and CVSS severity trends to board. Request dedicated patching resources for KEV-listed CVEs.",
             "Timeline": "≤30 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-006", "Priority": "🟠 High", "Stakeholder": "SOC Analysts", "Vendor": "Cisco",
             "Finding": "Ransomware Active Exploitation",
             "Action": "Monitor VPN authentication logs for brute force patterns against ASA endpoints. Set alerts for authentication failures exceeding threshold. Block known Akira and LockBit infrastructure IPs.",
             "Timeline": "≤7 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-007", "Priority": "🟡 Medium", "Stakeholder": "CISOs & Leadership", "Vendor": "All Vendors",
             "Finding": "Vendor Concentration Risk",
             "Action": "Commission a vendor risk assessment covering Microsoft, Cisco, and Google dependency mapping. Evaluate backup vendor options for critical infrastructure.",
             "Timeline": "≤90 Days", "CISA Directive": "DFARS 252.204-7012"},
            {"ID": "COA-008", "Priority": "🟡 Medium", "Stakeholder": "IT / Network Teams", "Vendor": "Microsoft",
             "Finding": "Tight Patch Windows",
             "Action": "Implement automated patch compliance reporting for all KEV-listed CVEs. Deploy SCCM/Intune compliance baselines. Establish emergency change control process for Critical CVEs.",
             "Timeline": "≤30 Days", "CISA Directive": "BOD 22-01"},
            {"ID": "COA-009", "Priority": "🟡 Medium", "Stakeholder": "SOC Analysts", "Vendor": "Google",
             "Finding": "Ransomware Active Exploitation",
             "Action": "Implement browser telemetry monitoring for Chrome process anomalies. Deploy endpoint detection rules for renderer process exploitation indicators.",
             "Timeline": "≤14 Days", "CISA Directive": "BOD 22-01"},
        ]

        coa_df = pd.DataFrame(coa_data)

        # 1. Create a sorting weight for Priority
        priority_map = {"🔴 Critical": 1, "🟠 High": 2, "🟡 Medium": 3}
        coa_df['p_sort'] = coa_df['Priority'].map(priority_map)
        
        # Sort by vendor then by priority weight
        coa_df = coa_df.sort_values(by=['Vendor', 'p_sort'])

        f1, f2 = st.columns(2)
        with f1:
            priority_filter = st.multiselect("Filter by Priority:",
                options=["🔴 Critical", "🟠 High", "🟡 Medium"],
                default=["🔴 Critical", "🟠 High", "🟡 Medium"],
                key="coa_priority_filter")
        with f2:
            stakeholder_filter = st.multiselect("Filter by Stakeholder:",
                options=["SOC Analysts", "IT / Network Teams", "CISOs & Leadership"],
                default=["SOC Analysts", "IT / Network Teams", "CISOs & Leadership"],
                key="coa_stakeholder_filter")

        # Apply filters
        filtered_coa = coa_df[
            (coa_df["Priority"].isin(priority_filter)) &
            (coa_df["Stakeholder"].isin(stakeholder_filter))
        ]

        # 2. Group by Vendor and create Expanders
        chart_header(
            "🎬 Courses of Action - List View",
            "These dropdowns are filterable course of actions based on vendors and criticality. We list the vendors which are used across all contractors.",
            "info_vendor_filter",
        )

        vendors = sorted(filtered_coa['Vendor'].unique())
        
        if not vendors:
            st.info("No actions match the selected filters.")
        
        for vendor in vendors:
            # Create a large dropdown (expander) for each company
            with st.expander(f"🏢 {vendor.upper()} - Action Items", expanded=False):
                vendor_specific_df = filtered_coa[filtered_coa['Vendor'] == vendor]
                
                for _, row in vendor_specific_df.iterrows():
                    priority_color = "#ef4444" if "Critical" in row["Priority"] else "#f97316" if "High" in row["Priority"] else "#fbbf24"
                    border_color = priority_color
                    bg_color = f"rgba({int(priority_color[1:3], 16)}, {int(priority_color[3:5], 16)}, {int(priority_color[5:7], 16)}, 0.05)"
                    
                    # Keep your original styling for the cards
                    st.markdown(f"""
                    <div style="background:{bg_color};border:1px solid {border_color}33;border-left:4px solid {border_color};
                                border-radius:0 12px 12px 0;padding:1rem 1.2rem;margin:0.6rem 0;">
                        <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.5rem;flex-wrap:wrap;">
                            <span style="font-family:'Space Mono',monospace;font-size:0.78rem;color:{priority_color};font-weight:700">{row['ID']}</span>
                            <span style="background:{priority_color}22;border:1px solid {priority_color}66;color:{priority_color};
                                        border-radius:999px;padding:0.1rem 0.6rem;font-size:0.72rem;font-weight:600">{row['Priority']}</span>
                            <span style="background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);color:#38bdf8;
                                        border-radius:999px;padding:0.1rem 0.6rem;font-size:0.72rem;">👤 {row['Stakeholder']}</span>
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.5rem;margin-bottom:0.75rem;">
                            <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                                <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Finding</div>
                                <div style="font-size:0.78rem;color:#cbd5e1;margin-top:0.15rem">{row['Finding']}</div>
                            </div>
                            <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                                <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Timeline</div>
                                <div style="font-size:0.78rem;color:{priority_color};margin-top:0.15rem;font-weight:600">{row['Timeline']}</div>
                            </div>
                            <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                                <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Directive</div>
                                <div style="font-size:0.78rem;color:#cbd5e1;margin-top:0.15rem">{row['CISA Directive']}</div>
                            </div>
                        </div>
                        <div style="font-size:0.87rem;color:#ffffff;line-height:1.5">{row['Action']}</div>
                    </div>""", unsafe_allow_html=True)

        chart_header(
            "🎬 Courses of Action - Table View",
            "The table below is based on the filters selected above, listing course of actions based on vendors and criticality. We list the vendors which are used across all contractors.",
            "info_vendor_filter",
        )
        st.dataframe(filtered_coa, use_container_width=True, hide_index=True)

        st.markdown('<div class="sub-header">📤 Export Courses of Action</div>', unsafe_allow_html=True)
        e1, e2 = st.columns(2)
        with e1:
            st.download_button(label="⬇️ Download as CSV",
                data=filtered_coa.to_csv(index=False),
                file_name=f"courses_of_action_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv", key="coa_csv_download")
        with e2:
            st.download_button(label="⬇️ Download as JSON",
                data=filtered_coa.to_json(orient="records", indent=2),
                file_name=f"courses_of_action_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json", key="coa_json_download")

        st.markdown("---")
        with st.expander("📚 Sources — Courses of Action"):
            for label, url in [
                ("CISA BOD 22-01", "https://www.cisa.gov/binding-operational-directive-22-01"),
                ("CISA Advisory AA24-038A", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"),
                ("Cisco PSIRT — CVE-2023-20198", "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"),
                ("Microsoft MSRC — CVE-2023-23397", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"),
                ("DFARS 252.204-7012", "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting."),
            ]:
                st.markdown(f"""<div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank" style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — DISSEMINATION STRATEGY
    # ════════════════════════════════════════════════════════════════════════
    with tab2:
        st.markdown('<div class="sub-header">Who gets what intelligence, when, and how</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="ops-card">
        A dissemination strategy defines how intelligence is packaged and delivered to each stakeholder.
        Different audiences need different formats — a SOC analyst needs technical CVE details,
        a CISO needs an executive risk summary, and an IT team needs a prioritized patch list.
        </div>
        """, unsafe_allow_html=True)

        dissem_data = [
            {"Intelligence Product": "KEV Patch Priority Report", "Audience": "IT / Network Teams",
             "Format": "CSV Export", "Cadence": "Weekly",
             "Content": "Ranked list of unpatched KEV CVEs by CVSS score and patch deadline. Includes vendor, product, CVE ID, and remediation steps.",
             "Channel": "Email / ITSM Ticket", "Classification": "Unclassified // FOUO"},
            {"Intelligence Product": "Ransomware Threat Alert", "Audience": "SOC Analysts",
             "Format": "JSON / STIX-like", "Cadence": "On New KEV Addition",
             "Content": "CVE details, ransomware probability score, confirmed threat actor TTPs, detection signatures, and recommended monitoring rules.",
             "Channel": "SIEM Alert / Slack", "Classification": "Unclassified // FOUO"},
            {"Intelligence Product": "Executive Vendor Risk Summary", "Audience": "CISOs & Leadership",
             "Format": "Dashboard View", "Cadence": "Monthly",
             "Content": "Vendor risk scores (0-100), CVSS severity trends, ransomware exposure percentage, MTTD/MTTR metrics, and compliance posture.",
             "Channel": "Board Presentation / Dashboard", "Classification": "Unclassified"},
            {"Intelligence Product": "Emerging Threat Bulletin", "Audience": "All Stakeholders",
             "Format": "PDF / Markdown", "Cadence": "As Needed",
             "Content": "New zero-day disclosures affecting contractor vendor stack, exploitation timeline, and immediate recommended actions.",
             "Channel": "Email Distribution List", "Classification": "Unclassified // FOUO"},
            {"Intelligence Product": "Compliance Gap Report", "Audience": "CISOs & Leadership",
             "Format": "CSV Export", "Cadence": "Quarterly",
             "Content": "CVEs past BOD 22-01 remediation deadline, DFARS 252.204-7012 compliance status, and False Claims Act exposure assessment.",
             "Channel": "Legal / Compliance Review", "Classification": "Unclassified // Sensitive"},
        ]

        dissem_df = pd.DataFrame(dissem_data)

        audience_filter = st.multiselect("Filter by Audience:",
            options=["IT / Network Teams", "SOC Analysts", "CISOs & Leadership", "All Stakeholders"],
            default=["IT / Network Teams", "SOC Analysts", "CISOs & Leadership", "All Stakeholders"],
            key="dissem_audience_filter")

        filtered_dissem = dissem_df[dissem_df["Audience"].isin(audience_filter)]

        st.markdown('<div class="sub-header">📡 Intelligence Products — Card View</div>', unsafe_allow_html=True)
        for _, row in filtered_dissem.iterrows():
            cadence_color = "#ef4444" if "New KEV" in row["Cadence"] else "#f97316" if "Weekly" in row["Cadence"] else "#38bdf8"
            st.markdown(f"""
            <div style="background:rgba(168,85,247,0.05);border:1px solid rgba(168,85,247,0.2);
                        border-left:4px solid #a855f7;border-radius:0 12px 12px 0;
                        padding:1rem 1.2rem;margin:0.6rem 0;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.6rem;flex-wrap:wrap;gap:0.4rem;">
                    <span style="font-size:0.95rem;font-weight:700;color:#a855f7">📄 {row['Intelligence Product']}</span>
                    <span style="background:rgba(100,116,139,0.15);border:1px solid rgba(100,116,139,0.3);color:#94a3b8;
                                 border-radius:999px;padding:0.1rem 0.7rem;font-size:0.7rem;">{row['Classification']}</span>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:0.5rem;margin-bottom:0.75rem;">
                    <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                        <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Audience</div>
                        <div style="font-size:0.78rem;color:#38bdf8;margin-top:0.15rem">👤 {row['Audience']}</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                        <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Format</div>
                        <div style="font-size:0.78rem;color:#cbd5e1;margin-top:0.15rem">📋 {row['Format']}</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                        <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Cadence</div>
                        <div style="font-size:0.78rem;color:{cadence_color};margin-top:0.15rem;font-weight:600">🔄 {row['Cadence']}</div>
                    </div>
                    <div style="background:rgba(255,255,255,0.03);border-radius:8px;padding:0.4rem 0.7rem;">
                        <div style="font-size:0.65rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em">Channel</div>
                        <div style="font-size:0.78rem;color:#cbd5e1;margin-top:0.15rem">📡 {row['Channel']}</div>
                    </div>
                </div>
                <div style="font-size:0.87rem;color:#ffffff;line-height:1.5">{row['Content']}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown('<div class="sub_header">📊 Dissemination Matrix — Table View</div>', unsafe_allow_html=True)
        st.dataframe(filtered_dissem, use_container_width=True, hide_index=True)

        st.markdown('<div class="sub-header">📤 Export Dissemination Matrix</div>', unsafe_allow_html=True)
        d1, d2 = st.columns(2)
        with d1:
            st.download_button(label="⬇️ Download as CSV",
                data=filtered_dissem.to_csv(index=False),
                file_name=f"dissemination_matrix_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv", key="dissem_csv_download")
        with d2:
            st.download_button(label="⬇️ Download as JSON",
                data=filtered_dissem.to_json(orient="records", indent=2),
                file_name=f"dissemination_matrix_{datetime.now().strftime('%Y%m%d')}.json",
                mime="application/json", key="dissem_json_download")

        # st.markdown('<div class="sub-header">🔄 Intelligence Flow — From Data to Stakeholder</div>', unsafe_allow_html=True)
        # flow_fig = go.Figure()
        # nodes = ["CISA KEV\nCatalog", "NIST NVD\nCVSS Scores", "CTI Platform\nAnalysis", "SOC\nAnalysts", "IT / Network\nTeams", "CISOs &\nLeadership"]
        # x_pos = [0, 0, 1, 2, 2, 2]
        # y_pos = [1, -1, 0, 1, 0, -1]
        # node_colors = ["#38bdf8", "#38bdf8", "#a855f7", "#ef4444", "#34d399", "#fbbf24"]

        # for node, x, y, color in zip(nodes, x_pos, y_pos, node_colors):
        #     flow_fig.add_trace(go.Scatter(
        #         x=[x], y=[y], mode="markers+text",
        #         marker=dict(size=50, color=color, opacity=0.8),
        #         text=[node], textposition="middle center",
        #         textfont=dict(size=9, color="#0f172a"), showlegend=False,
        #     ))

        # for src, dst in [(0, 2), (1, 2), (2, 3), (2, 4), (2, 5)]:
        #     flow_fig.add_trace(go.Scatter(
        #         x=[x_pos[src], x_pos[dst]], y=[y_pos[src], y_pos[dst]],
        #         mode="lines", line=dict(color="rgba(56,189,248,0.3)", width=2),
        #         showlegend=False,
        #     ))

        # flow_fig.update_layout(
        #     paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
        #     font_color="#cbd5e1",
        #     xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.5, 2.5]),
        #     yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.8, 1.8]),
        #     height=300, margin=dict(l=0, r=0, t=20, b=0),
        # )
        # st.plotly_chart(flow_fig, use_container_width=True)



        st.markdown('<div class="sub-header">🔄 Intelligence Flow — From Data to Stakeholder</div>', unsafe_allow_html=True)

        # 1. Defined Node Data with HTML breaks for better centering
        # We use <b> tags and <br> to force the text to stack properly inside the larger circles.
        nodes_config = {
            "cisa":  {"label": "<b>CISA KEV<br>Catalog</b>",      "pos": (0, 1),  "color": "#38bdf8"},
            "nist":  {"label": "<b>NIST NVD<br>CVSS</b>",         "pos": (0, -1), "color": "#38bdf8"},
            "cti":   {"label": "<b>CTI Platform<br>Analysis</b>", "pos": (1, 0),  "color": "#a855f7"},
            "soc":   {"label": "<b>SOC<br>Analysts</b>",          "pos": (2, 1),  "color": "#ef4444"},
            "it":    {"label": "<b>IT / Network<br>Teams</b>",     "pos": (2, 0),  "color": "#34d399"},
            "ciso":  {"label": "<b>CISOs &<br>Leadership</b>",    "pos": (2, -1), "color": "#fbbf24"},
        }

        edges = [
            ("cisa", "cti"), ("nist", "cti"),
            ("cti", "soc"), ("cti", "it"), ("cti", "ciso")
        ]

        flow_fig = go.Figure()

        # 2. Add Edges
        for src, dst in edges:
            x0, y0 = nodes_config[src]["pos"]
            x1, y1 = nodes_config[dst]["pos"]
            flow_fig.add_trace(go.Scatter(
                x=[x0, x1], y=[y0, y1],
                mode="lines",
                line=dict(color="rgba(56,189,248, 0.5)", width=3), # Slightly thicker lines
                hoverinfo="none",
                showlegend=False
            ))

        # 3. Add Nodes with much larger markers and text
        for key, data in nodes_config.items():
            flow_fig.add_trace(go.Scatter(
                x=[data["pos"][0]], 
                y=[data["pos"][1]],
                mode="markers+text",
                # Marker size increased from 50 to 110
                marker=dict(size=110, color=data["color"], opacity=1, 
                            line=dict(color="white", width=2)), # Added a white border for pop
                text=[data["label"]],
                textposition="middle center",
                # Text size increased to 12 and font family set for clarity
                textfont=dict(size=12, color="#0f172a", family="Arial Black"),
                hoverinfo="text",
                showlegend=False
            ))

        # 4. Expanded Layout to prevent edge clipping
        flow_fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", 
            plot_bgcolor="rgba(10,20,40,0.4)",
            font_color="#cbd5e1",
            # Slightly wider range so the 110px circles don't get cut off at the edges
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.6, 2.6]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.8, 1.8]),
            height=400, # Increased height for better vertical breathing room
            margin=dict(l=10, r=10, t=10, b=10),
        )

        st.plotly_chart(flow_fig, use_container_width=True)

        st.markdown("---")
        with st.expander("📚 Sources — Dissemination Strategy"):
            for label, url in [
                ("CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("CISA BOD 22-01", "https://www.cisa.gov/binding-operational-directive-22-01"),
                ("DFARS 252.204-7012", "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting."),
                ("NIST SP 800-150 — Guide to CTI Sharing", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf"),
            ]:
                st.markdown(f"""<div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                    border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank" style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)