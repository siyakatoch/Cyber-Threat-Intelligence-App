import streamlit as st
import pandas as pd
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import pages

def render():
    st.markdown('<div class="section-header">About Us</div>', unsafe_allow_html=True)
    st.markdown('<div class="info-box">Meet the team and learn about our roles for developing CTI.</div>', unsafe_allow_html=True)

    personas = [
        {
            "icon": "🫆",
            "name": "Sriya Kodali",
            "contributions": ["Stakeholders", "Intelligence Buy-In", "CTI Sourcing", "Linear Regression Analysis", "Ransomware Predition", "Triage Dashboard", "Intelligence & Dissemination"],
            "most_recent_contribute_date": "04/29/26",
        },
        {
            "icon": "🫆",
            "name": "Siya Katoch",
            "contributions": ["Dashboard", "CTI Sourcing", "Linear Regression Analysis", "Ransomware Predition", "Triage Dashboard", "Intelligence & Dissemination"],
            "most_recent_contribute_date": "04/29/26",
        },
        {
            "icon": "🫆",
            "name": "Kai Francis",
            "contributions": ["Threat Model", "Diamond Models", "Insights & Security", "CTI Sourcing", "Future CTI Directions"],
            "most_recent_contribute_date": "04/29/26",
        },
        {
            "icon": "🫆",
            "name": "Saket Yadav",
            "contributions": ["Trends & Assets", "Linear Regression Analysis", "Ransomware Predition", "Intelligence & Dissemination"],
            "most_recent_contribute_date": "04/29/26",
        },
        {
            "icon": "🫆",
            "name": "Emma Anhalt",
            "contributions": ["Background & Introduction", "Insights & Security", "CTI Sourcing"],
            "most_recent_contribute_date": "04/29/26",
        },
    ]

    for p in personas:
        st.markdown(f"""
        <div class="persona-card">
            <div class="persona-title"; style="font-size:1.5rem">{p['icon']} <strong style="font-size:1.5rem;letter-spacing:0.06em;font-family: 'Space Mono', monospace;">{p['name']}</strong></div>
            <div style="font-size:1rem;color:#7dd3fc;text-transform:uppercase;letter-spacing:0.06em">&emsp;&emsp;Contributions to Pages {''.join(f'<span class="badge">{s}</span>' for s in p['contributions'])}</div>
            <div style="text-indent: 2em;font-size:1rem;color:#7dd3fc;text-transform:uppercase;letter-spacing:0.06em">Most Recent Contribution Date: <strong style="font-size:1rem;color:#ffffff;letter-spacing:0.06em">{p['most_recent_contribute_date']}</strong></div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="section-header">Milestone Checklist</div>', unsafe_allow_html=True)

    st.markdown('<div class="info-box">See all features and requirements of our CTI App.</div>', unsafe_allow_html=True)
    
    requirements_1 = [
        "Introduction & Background",
        "Stakeholders",
        "Threat Model",
        "Trends & Assets",
        "Diamond Models",
        "Dashboard"
        "Intelligence Buy-In",
        "About Us & Checklist"
    ]

    checklist_items = ''.join(
        f'<div style="margin: 6px 0;"><input type="checkbox" checked disabled> {item}</div>'
        for item in requirements_1
    )

    st.markdown(f"""
        <div class="info-box">
            <div class="persona-title" style="font-size:1.5rem">
                <strong style="font-size:1.5rem; letter-spacing:0.06em; font-family: 'Space Mono', monospace;">
                    Milestone 1
                </strong>
            </div>
            <div style="margin-top: 10px;">
                {checklist_items}
            </div>
        </div>
    """, unsafe_allow_html=True)

    requirements_2 = [
        "CTI Data Source Identification and Justification",
        "Collection Strategies and Data Summary",
        "Dynamic Data Explorer",
        "Minimum Data Expectations",
        "Reproducibility Requirements",
        "Ethics and Data Governance",
        "Security-Aware Development Practices",
        "Group Roles (About Us & Checklist)"
    ]

    checklist_items = ''.join(
        f'<div style="margin: 6px 0;"><input type="checkbox" checked disabled> {item}</div>'
        for item in requirements_2
    )

    st.markdown(f"""
        <div class="info-box">
            <div class="persona-title" style="font-size:1.5rem">
                <strong style="font-size:1.5rem; letter-spacing:0.06em; font-family: 'Space Mono', monospace;">
                    Milestone 2
                </strong>
            </div>
            <div style="margin-top: 10px;">
                {checklist_items}
            </div>
        </div>
    """, unsafe_allow_html=True)


    requirements_3 = [
        "Analytical Approaches and Justification",
        "Interactive Analytics Panel",
        "Operational Metrics",
        "Validation and Error Analysis",
        "Preliminary Visualizations",
        "Key Insights and Intelligence Summary"
    ]

    checklist_items = ''.join(
        f'<div style="margin: 6px 0;"><input type="checkbox" checked disabled> {item}</div>'
        for item in requirements_3
    )

    st.markdown(f"""
        <div class="info-box">
            <div class="persona-title" style="font-size:1.5rem">
                <strong style="font-size:1.5rem; letter-spacing:0.06em; font-family: 'Space Mono', monospace;">
                    Milestone 3
                </strong>
            </div>
            <div style="margin-top: 10px;">
                {checklist_items}
            </div>
        </div>
    """, unsafe_allow_html=True)


    requirements_4 = [
        "Key Insights and Intelligence Summary",
        "Operational Intelligence and Dissemination",
        "Operational Triage Dashboard",
        "Role-Based Views",
        "Actionable Outputs",
        "Future CTI Platform Directions"
    ]

    checklist_items = ''.join(
        f'<div style="margin: 6px 0;"><input type="checkbox" checked disabled> {item}</div>'
        for item in requirements_4
    )

    st.markdown(f"""
        <div class="info-box">
            <div class="persona-title" style="font-size:1.5rem">
                <strong style="font-size:1.5rem; letter-spacing:0.06em; font-family: 'Space Mono', monospace;">
                    Milestone 4
                </strong>
            </div>
            <div style="margin-top: 10px;">
                {checklist_items}
            </div>
        </div>
    """, unsafe_allow_html=True)