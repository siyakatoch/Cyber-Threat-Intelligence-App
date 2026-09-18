import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score, mean_absolute_error
import warnings
warnings.filterwarnings("ignore")


# ── Load & Clean Data ─────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    kev = pd.read_json("Defense_KEV_Entries.json")
    cvss = pd.read_json("Data_with_Scores.json")

    # Clean CVSS numeric fields — handle "N/A" and "~5.0" strings
    for col in ["Base", "Impact", "Exploitability"]:
        cvss[col] = cvss[col].apply(
            lambda x: float(str(x).replace("~", "").strip())
            if str(x).replace("~", "").replace(".", "").isdigit()
            or (str(x).replace("~", "").replace(".", "").lstrip("-").isdigit())
            else np.nan
        )

    # Parse dates
    kev["Date Added"] = pd.to_datetime(kev["Date Added"])
    kev["Due Date"] = pd.to_datetime(kev["Due Date"])
    kev["Year"] = kev["Date Added"].dt.year
    kev["Month"] = kev["Date Added"].dt.to_period("M").astype(str)

    # Merge
    merged = kev.merge(
        cvss[["CVE ID", "Base", "Impact", "Exploitability"]],
        on="CVE ID", how="left"
    )
    return kev, cvss, merged



def chart_header(title, tooltip, key=None):
    st.markdown(f"""
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
            <div class="sub-header">{title}</div>
            <div class="tooltip-icon">
                ⓘ<span class="tooltip-text">{tooltip}</span>
            </div>
        </div>
    """, unsafe_allow_html=True)


def render():
    kev_df, cvss_df, merged_df = load_data()

    # ── CSS ───────────────────────────────────────────────────────────────────
    st.markdown("""
    <style>
    .insight-card {
        background: rgba(14,165,233,0.06);
        border: 1px solid rgba(56,189,248,0.18);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
        color: #ffffff;
    }
    .insight-kpi {
        background: rgba(14,165,233,0.06);
        border: 1px solid rgba(56,189,248,0.18);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        text-align: center;
    }
    .insight-kpi-value {
        font-family: 'Space Mono', monospace;
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .insight-kpi-label {
        font-size: 0.72rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        margin-top: 0.3rem;
    }
    .insight-kpi-delta { font-size: 0.72rem; color: #f97316; margin-top: 0.2rem; }
    .insight-kpi-delta-red { font-size: 0.72rem; color: #ef4444; margin-top: 0.2rem; }
    .insight-kpi-delta-green { font-size: 0.72rem; color: #34d399; margin-top: 0.2rem; }
    .model-box {
        background: rgba(239,68,68,0.05);
        border: 1px solid rgba(239,68,68,0.2);
        border-left: 3px solid #ef4444;
        border-radius: 0 10px 10px 0;
        padding: 0.9rem 1.2rem;
        margin: 0.5rem 0;
        color: #ffffff;
        font-size: 0.87rem;
    }
    .forecast-box {
        background: rgba(34,197,94,0.05);
        border: 1px solid rgba(34,197,94,0.2);
        border-left: 3px solid #22c55e;
        border-radius: 0 10px 10px 0;
        padding: 0.9rem 1.2rem;
        margin: 0.5rem 0;
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

    # ── Page Header ───────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">🔮 Predictive Insights — Vendor CVE Forecasting</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="insight-card">
    This page applies <strong>linear regression models</strong> to your CISA KEV and CVSS data to answer 
    two forward-looking questions: <br><br>
    1️⃣ <strong>How many new exploited CVEs should we expect per vendor?</strong> — Volume forecasting using KEV date trends<br>
    2️⃣ <strong>Are CVSS scores getting worse or better per vendor?</strong> — Severity forecasting using historical Base scores<br><br>
    All predictions are generated from your actual dataset using scikit-learn's LinearRegression model. 
    Forecasts extend to <strong>2027</strong> based on patterns in the 2025–2026 data.
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div class="insight-card" style="background: rgba(240,230,67,0.05); border: 1px solid rgba(240,230,67,0.2);">
    ⚠️ The analytics on this page are not the most accurate for prediction usage because of the limitations caused by our small sample size. 
                We address this in <em>CTI Sourcing's Metrics & Validation</em> tab. 
                We include future course of actions for this limitation in the <em>Future CTI Directions</em> page.
    </div>
    """, unsafe_allow_html=True)

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs([
        "🎯 Vendor Risk Score",
        "📈 CVSS Score Forecast",
        "🧠 Model Summary"
    ])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — VENDOR RISK SCORE PREDICTOR
    # ════════════════════════════════════════════════════════════════════════
    with tab1:
        st.markdown('<div class="sub-header">Which vendors pose the greatest risk to defense contractors?</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        Using your actual CISA KEV and CVSS data, this model calculates a <strong>weighted risk score</strong>
        for each vendor by combining five real data points:<br><br>
        🔴 <strong>Base CVSS Score</strong> — raw severity from NIST NVD or vendor advisory<br>
        🟠 <strong>Impact Score</strong> — how much damage exploitation causes<br>
        🟡 <strong>Exploitability Score</strong> — how easy it is to exploit<br>
        ☣️ <strong>Ransomware Use</strong> — confirmed ransomware exploitation adds significant weight<br>
        ⏱️ <strong>Patch Urgency</strong> — tighter CISA remediation windows = higher risk<br><br>
        Scores are normalized to <strong>0–100</strong>. A linear regression model then identifies 
        which individual CVE features are the strongest predictors of overall vendor risk.
        </div>
        """, unsafe_allow_html=True)

        colors = {
            "Microsoft": "#60a5fa",
            "Cisco": "#34d399",
            "Google": "#f87171",
            "Fortinet": "#fb923c",
            "Ivanti": "#a78bfa",
            "Apple": "#fbbf24",
            "Linux": "#94a3b8",
            "VMware": "#22d3ee",
            "Citrix": "#e879f9",
            "Broadcom": "#f43f5e",
            "SAP": "#facc15",
            "Oracle": "#4ade80",
        }

        # ── Build risk scores ──
        risk_df = merged_df.copy()

        # Ransomware binary
        risk_df["Ransomware Score"] = risk_df["Ransomware Use"].apply(
            lambda x: 10 if x == "Known" else 0
        )

        # Patch urgency — tighter window = higher urgency
        risk_df["Days Window"] = (risk_df["Due Date"] - risk_df["Date Added"]).dt.days
        max_days = risk_df["Days Window"].max()
        risk_df["Urgency Score"] = risk_df["Days Window"].apply(
            lambda x: round((1 - (x / max_days)) * 10, 2) if pd.notna(x) and max_days > 0 else 0
        )

        # Fill missing CVSS values with vendor median
        for col in ["Base", "Impact", "Exploitability"]:
            risk_df[col] = risk_df.groupby("Vendor / Project")[col].transform(
                lambda x: x.fillna(x.median())
            )

        # Weighted risk score (weights sum to 1.0)
        risk_df["Risk Score Raw"] = (
            risk_df["Base"]            * 0.35 +   # weight 35%
            risk_df["Impact"]          * 0.25 +   # weight 25%
            risk_df["Exploitability"]  * 0.20 +   # weight 20%
            risk_df["Ransomware Score"]* 0.10 +   # weight 10%
            risk_df["Urgency Score"]   * 0.10     # weight 10%
        )

        # Normalize to 0-100
        min_score = risk_df["Risk Score Raw"].min()
        max_score = risk_df["Risk Score Raw"].max()
        risk_df["Risk Score"] = risk_df["Risk Score Raw"].apply(
            lambda x: round(((x - min_score) / (max_score - min_score)) * 100, 1)
        )

        # ── Vendor-level aggregation ──
        vendor_risk = (
            risk_df.groupby("Vendor / Project")
            .agg(
                Avg_Risk_Score=("Risk Score", "mean"),
                Avg_CVSS=("Base", "mean"),
                Avg_Impact=("Impact", "mean"),
                Avg_Exploitability=("Exploitability", "mean"),
                Ransomware_CVEs=("Ransomware Score", lambda x: (x > 0).sum()),
                CVE_Count=("CVE ID", "count"),
            )
            .reset_index()
            .rename(columns={"Vendor / Project": "Vendor"})
        )
        vendor_risk["Avg_Risk_Score"] = vendor_risk["Avg_Risk_Score"].round(1)
        vendor_risk["Avg_CVSS"] = vendor_risk["Avg_CVSS"].round(2)
        vendor_risk = vendor_risk.sort_values("Avg_Risk_Score", ascending=False)

        # ── Vendor filter ──
        all_vendors = vendor_risk["Vendor"].tolist()
        selected_vendors = st.multiselect(
            "Filter Vendors:",
            options=all_vendors,
            default=all_vendors[:8],
            key="risk_vendor_filter"
        )

        if not selected_vendors:
            st.warning("Please select at least one vendor.")
        else:
            filtered_risk = vendor_risk[vendor_risk["Vendor"].isin(selected_vendors)]

            # ── KPI Cards — Top 4 riskiest ──
            st.markdown("---")
            st.markdown('<div class="sub-header">🔴 Highest Risk Vendors</div>', unsafe_allow_html=True)
            top4 = filtered_risk.head(4)
            kpi_cols = st.columns(4)
            for i, (_, row) in enumerate(top4.iterrows()):
                with kpi_cols[i]:
                    score = row["Avg_Risk_Score"]
                    color = "#ef4444" if score >= 70 else "#f97316" if score >= 50 else "#38bdf8"
                    st.markdown(f"""
                    <div class="insight-kpi">
                        <div class="insight-kpi-value" style="color:{color}">{score}</div>
                        <div class="insight-kpi-label">{row['Vendor']}</div>
                        <div class="insight-kpi-delta">Avg CVSS: {row['Avg_CVSS']} | {int(row['CVE_Count'])} CVEs</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # ── Horizontal bar chart — Risk Score ──
            chart_header("📊 Vendor Risk Score Ranking (0–100)",
                "This chart ranks each vendor by their overall weighted risk score (0–100). The score combines Base CVSS severity (35%), Impact (25%), Exploitability (20%), Ransomware Use (10%), and Patch Urgency (10%). Red dashed line = High Risk threshold (70). Orange dashed line = Medium Risk threshold (50).",
                "info_risk_ranking")
            fig_risk = px.bar(
                filtered_risk.sort_values("Avg_Risk_Score"),
                x="Avg_Risk_Score", y="Vendor",
                orientation="h",
                color="Vendor",
                color_discrete_map=colors,
                template="plotly_dark",
                text="Avg_Risk_Score",
            )
            fig_risk.add_vline(
                x=70, line_dash="dash", line_color="#ef4444",
                annotation_text="High Risk (70)",
                annotation_font_color="#ef4444",
            )
            fig_risk.add_vline(
                x=50, line_dash="dash", line_color="#f97316",
                annotation_text="Medium Risk (50)",
                annotation_font_color="#f97316",
            )
            fig_risk.update_traces(textposition="outside")
            fig_risk.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1",
                showlegend=False,
                xaxis=dict(range=[0, 115], title="Risk Score (0–100)", gridcolor="#1e3a5f"),
                yaxis=dict(autorange="reversed"),
                height=400,
                margin=dict(l=0, r=60, t=20, b=0),
            )
            st.plotly_chart(fig_risk, use_container_width=True)

            # ── Linear Regression — Feature Importance ──
            chart_header("🧠 Linear Regression — Which Factors Drive Risk Most?",
                "This chart shows the regression coefficients for each feature used in the risk score model. A higher coefficient means that feature has a stronger influence on the overall risk score. Base CVSS and Impact typically dominate because they carry the most weight in the scoring formula.",
                "info_feature_importance")
            st.markdown("""
            <div class="insight-card" style="font-size:0.85rem">
            A linear regression model is trained on the individual CVE features to identify which factors
            are the strongest predictors of overall risk score. <strong>Higher coefficient = stronger driver of risk.</strong>
            </div>
            """, unsafe_allow_html=True)

            model_df = risk_df[["Base", "Impact", "Exploitability", "Ransomware Score", "Urgency Score", "Risk Score"]].dropna()
            if len(model_df) > 5:
                X_feat = model_df[["Base", "Impact", "Exploitability", "Ransomware Score", "Urgency Score"]].values
                y_feat = model_df["Risk Score"].values

                reg = LinearRegression()
                reg.fit(X_feat, y_feat)
                r2 = r2_score(y_feat, reg.predict(X_feat))

                coef_df = pd.DataFrame({
                    "Feature": ["Base CVSS", "Impact Score", "Exploitability", "Ransomware Use", "Patch Urgency"],
                    "Coefficient": [round(c, 3) for c in reg.coef_],
                    "Interpretation": [
                        "Higher CVSS → Higher risk",
                        "Greater damage impact → Higher risk",
                        "Easier to exploit → Higher risk",
                        "Confirmed ransomware use → Significant risk boost",
                        "Tighter patch window → Higher urgency",
                    ]
                }).sort_values("Coefficient", ascending=False)

                fig_coef = px.bar(
                    coef_df.sort_values("Coefficient"),
                    x="Coefficient", y="Feature",
                    orientation="h",
                    color="Coefficient",
                    color_continuous_scale=["#1e3a5f", "#0ea5e9", "#ef4444"],
                    template="plotly_dark",
                    text="Coefficient",
                )
                fig_coef.update_traces(textposition="outside")
                fig_coef.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(10,20,40,0.6)",
                    font_color="#cbd5e1",
                    coloraxis_showscale=False,
                    xaxis_title="Regression Coefficient",
                    yaxis=dict(autorange="reversed"),
                    height=300,
                    margin=dict(l=0, r=60, t=20, b=0),
                )
                st.plotly_chart(fig_coef, use_container_width=True)

                # R² metric
                r2_col1, r2_col2, r2_col3 = st.columns(3)
                with r2_col1:
                    st.markdown(f"""
                    <div class="insight-kpi">
                        <div class="insight-kpi-value">{r2:.3f}</div>
                        <div class="insight-kpi-label">R² Score</div>
                        <div class="insight-kpi-delta">Model fit quality</div>
                    </div>""", unsafe_allow_html=True)
                with r2_col2:
                    top_feature = coef_df.iloc[0]["Feature"]
                    st.markdown(f"""
                    <div class="insight-kpi">
                        <div class="insight-kpi-value" style="font-size:1.1rem">{top_feature}</div>
                        <div class="insight-kpi-label">Top Risk Driver</div>
                        <div class="insight-kpi-delta">Highest coefficient</div>
                    </div>""", unsafe_allow_html=True)
                with r2_col3:
                    st.markdown(f"""
                    <div class="insight-kpi">
                        <div class="insight-kpi-value">{len(model_df)}</div>
                        <div class="insight-kpi-label">CVEs in Model</div>
                        <div class="insight-kpi-delta">Training data points</div>
                    </div>""", unsafe_allow_html=True)

            # ── Full Risk Table ──
            st.markdown(f"""<div><br></div>""", unsafe_allow_html=True)
            chart_header("📋 Full Vendor Risk Breakdown",
                "This table shows the aggregated risk metrics per vendor — average risk score, average CVSS, average impact, average exploitability, number of ransomware-confirmed CVEs, and total CVE count. Use this to compare vendors side by side.",
                "info_risk_table")
            display_risk = filtered_risk.rename(columns={
                "Avg_Risk_Score": "Risk Score (0–100)",
                "Avg_CVSS": "Avg Base CVSS",
                "Avg_Impact": "Avg Impact",
                "Avg_Exploitability": "Avg Exploitability",
                "Ransomware_CVEs": "Ransomware CVEs",
                "CVE_Count": "Total CVEs",
            })
            st.dataframe(display_risk, use_container_width=True, hide_index=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — CVSS SCORE FORECAST
    # ════════════════════════════════════════════════════════════════════════
    with tab2:
        st.markdown('<div class="sub-header">Are vendor CVSS scores trending more or less severe over time?</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        Using the <strong>Base CVSS score</strong> from NIST NVD for each CVE, we calculate the average 
        severity per vendor per year and train a linear regression model to predict the 
        <strong>expected average CVSS score in 2026 and 2027</strong>. A rising trendline means that 
        vendor's vulnerabilities are getting more severe over time — a critical signal for contractors 
        managing patch prioritization across Microsoft, Cisco, and Google environments.
        </div>
        """, unsafe_allow_html=True)

        # ── Vendor filter ──
        cvss_vendors = merged_df.dropna(subset=["Base"])["Vendor / Project"].value_counts().head(8).index.tolist()
        selected_cvss_vendors = st.multiselect(
            "Select Vendors:",
            options=cvss_vendors,
            default=["Microsoft", "Cisco", "Google", "Fortinet", "Ivanti"]
            if all(v in cvss_vendors for v in ["Microsoft", "Cisco", "Google", "Fortinet", "Ivanti"])
            else cvss_vendors[:5],
            key="cvss_vendor_filter"
        )

        if not selected_cvss_vendors:
            st.warning("Please select at least one vendor.")
        else:
            # ── Compute avg CVSS per vendor per year ──
            avg_cvss = (
                merged_df[
                    (merged_df["Vendor / Project"].isin(selected_cvss_vendors)) &
                    (merged_df["Base"].notna())
                ]
                .groupby(["Year", "Vendor / Project"])["Base"]
                .mean()
                .reset_index()
                .rename(columns={"Base": "Avg CVSS"})
            )

            forecast_years = [2026, 2027]
            cvss_historical = []
            cvss_forecast = []
            cvss_model_stats = []

            for vendor in selected_cvss_vendors:
                vdata = avg_cvss[avg_cvss["Vendor / Project"] == vendor].sort_values("Year")
                if len(vdata) < 2:
                    # Single year — still show it
                    for _, row in vdata.iterrows():
                        cvss_historical.append({
                            "Year": row["Year"],
                            "Vendor / Project": vendor,
                            "Avg CVSS": round(row["Avg CVSS"], 2),
                            "Type": "Actual"
                        })
                    continue

                X = vdata[["Year"]].values
                y = vdata["Avg CVSS"].values

                model = LinearRegression()
                model.fit(X, y)

                r2 = r2_score(y, model.predict(X))
                mae = mean_absolute_error(y, model.predict(X))

                cvss_model_stats.append({
                    "Vendor": vendor,
                    "Slope (CVSS/yr)": round(model.coef_[0], 3),
                    "R² Score": round(r2, 3),
                    "MAE": round(mae, 3),
                    "2026 Predicted Avg CVSS": round(min(10.0, max(0, model.predict([[2026]])[0])), 2),
                    "2027 Predicted Avg CVSS": round(min(10.0, max(0, model.predict([[2027]])[0])), 2),
                    "Trend": "📈 Getting Worse" if model.coef_[0] > 0 else "📉 Getting Better"
                })

                for _, row in vdata.iterrows():
                    cvss_historical.append({
                        "Year": row["Year"],
                        "Vendor / Project": vendor,
                        "Avg CVSS": round(row["Avg CVSS"], 2),
                        "Type": "Actual"
                    })

                for yr in forecast_years:
                    pred = round(min(10.0, max(0, model.predict([[yr]])[0])), 2)
                    cvss_forecast.append({
                        "Year": yr,
                        "Vendor / Project": vendor,
                        "Avg CVSS": pred,
                        "Type": "Forecast"
                    })

            # ── KPI Cards ──
            st.markdown("---")
            st.markdown('<div class="sub-header">🎯 Predicted Average CVSS Score — 2027</div>', unsafe_allow_html=True)
            kpi_cols2 = st.columns(len(selected_cvss_vendors))
            for i, vendor in enumerate(selected_cvss_vendors):
                vstat = next((s for s in cvss_model_stats if s["Vendor"] == vendor), None)
                if vstat:
                    with kpi_cols2[i]:
                        score = vstat["2027 Predicted Avg CVSS"]
                        color_class = "insight-kpi-delta-red" if score >= 9.0 else "insight-kpi-delta"
                        st.markdown(f"""
                        <div class="insight-kpi">
                            <div class="insight-kpi-value" style="color:{'#ef4444' if score >= 9.0 else '#38bdf8'}">{score}</div>
                            <div class="insight-kpi-label">{vendor}</div>
                            <div class="{color_class}">{vstat['Trend']}</div>
                        </div>
                        """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # ── CVSS Forecast Chart ──
            combined_cvss = pd.DataFrame(cvss_historical + cvss_forecast)

            fig2 = go.Figure()
            colors = {
                "Microsoft": "#60a5fa",
                "Cisco": "#34d399",
                "Google": "#f87171",
                "Fortinet": "#fb923c",
                "Ivanti": "#a78bfa",
                "Apple": "#fbbf24",
                "Linux": "#94a3b8",
                "VMware": "#22d3ee",
            }

            for vendor in selected_cvss_vendors:
                color = colors.get(vendor, "#ffffff")
                vactual = combined_cvss[(combined_cvss["Vendor / Project"] == vendor) & (combined_cvss["Type"] == "Actual")]
                vforecast_df = combined_cvss[(combined_cvss["Vendor / Project"] == vendor) & (combined_cvss["Type"] == "Forecast")]

                fig2.add_trace(go.Scatter(
                    x=vactual["Year"], y=vactual["Avg CVSS"],
                    mode="lines+markers",
                    name=f"{vendor} (Actual)",
                    line=dict(color=color, width=2),
                    marker=dict(size=8),
                ))

                if not vactual.empty and not vforecast_df.empty:
                    last_actual = vactual.sort_values("Year").iloc[-1]
                    first_forecast = vforecast_df.sort_values("Year").iloc[0]
                    fig2.add_trace(go.Scatter(
                        x=[last_actual["Year"], first_forecast["Year"]],
                        y=[last_actual["Avg CVSS"], first_forecast["Avg CVSS"]],
                        mode="lines",
                        line=dict(color=color, width=2, dash="dot"),
                        showlegend=False,
                    ))

                fig2.add_trace(go.Scatter(
                    x=vforecast_df["Year"], y=vforecast_df["Avg CVSS"],
                    mode="lines+markers",
                    name=f"{vendor} (Forecast)",
                    line=dict(color=color, width=2, dash="dash"),
                    marker=dict(size=10, symbol="diamond"),
                ))

            # Critical threshold line
            fig2.add_hline(
                y=9.0, line_dash="dash", line_color="#ef4444",
                annotation_text="Critical Threshold (CVSS 9.0)",
                annotation_position="top left",
                annotation_font_color="#ef4444",
            )

            # Forecast zone
            fig2.add_vrect(
                x0=2025.5, x1=2027.5,
                fillcolor="rgba(239,68,68,0.05)",
                layer="below", line_width=0,
                annotation_text="Forecast Zone",
                annotation_position="top left",
                annotation_font_color="#ef4444",
                annotation_font_size=11,
            )

            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1",
                legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10)),
                xaxis=dict(
                    title="Year",
                    gridcolor="#1e3a5f",
                    tickmode="linear",
                    dtick=1,
                ),
                yaxis=dict(
                    title="Average CVSS Base Score",
                    gridcolor="#1e3a5f",
                    range=[5, 11],
                ),
                height=420,
                margin=dict(l=0, r=0, t=20, b=0),
            )
            st.plotly_chart(fig2, use_container_width=True)

            # ── CVSS Model Stats Table ──
            chart_header("📋 Model Predictions — Average CVSS by Vendor",
                "This table shows the linear regression output for each vendor — the slope (how fast severity is changing per year), R² score (model fit quality), MAE (average prediction error), and predicted average CVSS scores for 2026 and 2027. A positive slope means vulnerabilities are getting more severe.",
                "info_cvss_stats")
            if cvss_model_stats:
                stats_df = pd.DataFrame(cvss_model_stats)
                st.dataframe(stats_df, use_container_width=True, hide_index=True)

            # ── CVSS Distribution by Vendor ──
            chart_header("📊 Current CVSS Score Distribution by Vendor",
                "This box plot shows the spread of CVSS scores for each vendor's CVEs in the dataset. The box shows the middle 50% of scores, the line inside is the median, and dots are individual CVEs. The red dashed line marks the Critical threshold (9.0). Vendors with boxes above 9.0 consistently produce critical severity vulnerabilities.",
                "info_cvss_dist")
            cvss_box = merged_df[
                (merged_df["Vendor / Project"].isin(selected_cvss_vendors)) &
                (merged_df["Base"].notna())
            ]
            fig3 = px.box(
                cvss_box, x="Vendor / Project", y="Base",
                color="Vendor / Project",
                color_discrete_map=colors,
                template="plotly_dark",
                points="all",
            )
            fig3.add_hline(
                y=9.0, line_dash="dash", line_color="#ef4444",
                annotation_text="Critical (9.0)",
                annotation_font_color="#ef4444",
            )
            fig3.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1",
                showlegend=False,
                xaxis_title="Vendor",
                yaxis_title="CVSS Base Score",
                margin=dict(l=0, r=0, t=20, b=0),
            )
            st.plotly_chart(fig3, use_container_width=True)

            # ── Exploitation Speed ──
            chart_header("⚡ Exploitation Speed — Days From Disclosure to KEV Addition",
                "This chart shows the average number of days between when a CVE is added to the CISA KEV catalog and when the remediation deadline hits. Shorter bars mean tighter patch windows — contractors have less time to respond. Use this to set internal SLA targets for each vendor's CVEs.",
                "info_exploit_speed")
            st.markdown("""
            <div class="insight-card" style="font-size:0.85rem">
            The gap between when a CVE is publicly disclosed and when CISA confirms active exploitation 
            is shrinking. This chart shows average days to exploitation per vendor — the shorter the bar, 
            the faster contractors need to act after a patch is released.
            </div>
            """, unsafe_allow_html=True)

            speed_df = merged_df[merged_df["Vendor / Project"].isin(selected_cvss_vendors)].copy()
            speed_df["Days to KEV"] = (speed_df["Due Date"] - speed_df["Date Added"]).dt.days
            avg_speed = (
                speed_df.groupby("Vendor / Project")["Days to KEV"]
                .mean()
                .reset_index()
                .rename(columns={"Days to KEV": "Avg Days to Remediation"})
                .sort_values("Avg Days to Remediation")
            )
            avg_speed["Avg Days to Remediation"] = avg_speed["Avg Days to Remediation"].round(1)

            fig4 = px.bar(
                avg_speed, x="Avg Days to Remediation", y="Vendor / Project",
                orientation="h",
                color="Vendor / Project",
                color_discrete_map=colors,
                template="plotly_dark",
                text="Avg Days to Remediation",
            )
            fig4.update_traces(textposition="outside")
            fig4.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1",
                showlegend=False,
                xaxis_title="Average Days (Date Added → Due Date)",
                yaxis=dict(autorange="reversed"),
                margin=dict(l=0, r=60, t=20, b=0),
            )
            st.plotly_chart(fig4, use_container_width=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — MODEL SUMMARY
    # ════════════════════════════════════════════════════════════════════════
    with tab3:
        st.markdown('<div class="sub-header">🧠 How the Models Work</div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="insight-card">
        <strong style="color:#38bdf8">Model: scikit-learn LinearRegression</strong><br><br>
        Linear regression finds the best-fit straight line through historical data points and extends 
        it into the future. It answers: <em>"If the current trend continues, what value should we expect 
        next year?"</em><br><br>
        <strong>Input (X):</strong> Year (2025, 2026, etc.)<br>
        <strong>Output (y):</strong> Either CVE count per vendor (Volume model) or average CVSS score per vendor (Severity model)<br><br>
        <strong>Model equation:</strong> y = slope × year + intercept<br>
        A <strong>positive slope</strong> means the metric is increasing year over year.<br>
        A <strong>negative slope</strong> means it is decreasing.
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sub-header">📏 Model Evaluation Metrics</div>', unsafe_allow_html=True)
        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown("""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="font-size:1.2rem">R² Score</div>
                <div class="insight-kpi-label">Goodness of Fit</div>
                <div class="insight-kpi-delta">1.0 = perfect fit<br>0.0 = no fit</div>
            </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown("""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="font-size:1.2rem">MAE</div>
                <div class="insight-kpi-label">Mean Absolute Error</div>
                <div class="insight-kpi-delta">Average prediction error<br>Lower = more accurate</div>
            </div>
            """, unsafe_allow_html=True)
        with m3:
            st.markdown("""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="font-size:1.2rem">Slope</div>
                <div class="insight-kpi-label">Rate of Change</div>
                <div class="insight-kpi-delta">+ = getting worse<br>− = getting better</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">⚠️ Model Limitations</div>', unsafe_allow_html=True)
        limitations = [
            "R² near 1.0 on the Vendor Risk Score model is mathematically guaranteed — not meaningful. The target variable (Risk Score) is a direct linear combination of the same features used in the regression (Base, Impact, Exploitability, Ransomware, Urgency). This means the model is essentially rediscovering its own formula. The coefficient chart is useful for showing relative feature weights, but R² here should not be interpreted as model accuracy.",
            "R² = 1.0 and MAE = 0.0 on the CVSS Forecast are also mathematically certain — not impressive results. With only 2 data points per vendor (2025 and 2026), a linear regression line will always pass through both points perfectly. Two points always define a perfect line by definition. These forecasts are directional estimates only — not statistically validated predictions.",
            "Small dataset — with only 100 CVEs across 2 years, linear regression provides directional trends rather than precise predictions. More historical data would significantly improve accuracy and statistical validity.",
            "Linear assumption — real-world CVE trends are not always linear. A sudden zero-day campaign or vendor patch overhaul can cause sharp spikes not captured by a linear model.",
            "No external variables — the CVSS forecast model uses only year as a predictor. In reality, CVSS scores are influenced by vulnerability type, patch cadence, and threat actor focus.",
            "CVSS score ceiling — CVSS scores are capped at 10.0. Predictions are clipped to this range, which may compress forecast accuracy for vendors already near the ceiling.",
            "Forecasts are directional — use these predictions to prioritize vendor attention, not as exact values. Treat the 2027 numbers as informed estimates, not guarantees.",
        ]
        for lim in limitations:
            st.markdown(f'<div class="model-box">⚠️ {lim}</div>', unsafe_allow_html=True)

        st.markdown('<div class="sub-header">✅ How to Use These Insights</div>', unsafe_allow_html=True)
        recommendations = [
            "Vendors with increasing CVSS slope should be prioritized for proactive patch management — their vulnerabilities are trending more severe.",
            "Vendors with high forecast CVE volume AND high predicted CVSS scores represent the highest combined risk — allocate more SOC resources there.",
            "Use the exploitation speed chart to set internal SLA targets — if a vendor's CVEs are typically patched within 21 days per CISA, your team should target 14 days.",
            "Share the 2027 forecast table with your CISO or security leadership as a data-driven case for vendor risk investment.",
            "Revisit these models quarterly as new KEV entries are added — the more data, the more reliable the forecast.",
        ]
        for rec in recommendations:
            st.markdown(f'<div class="forecast-box">✅ {rec}</div>', unsafe_allow_html=True)

        # ── Raw data summary ──
        st.markdown("---")
        chart_header("📂 Dataset Summary",
            "These KPI cards summarize the full dataset used to train both models on this page — total CVEs, unique vendors tracked, overall average CVSS score across all CVEs, and the percentage of CVEs confirmed as ransomware-linked by CISA.",
            "info_dataset_summary")
        d1, d2, d3, d4 = st.columns(4)
        with d1:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{len(merged_df)}</div>
                <div class="insight-kpi-label">Total CVEs</div>
            </div>""", unsafe_allow_html=True)
        with d2:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{merged_df['Vendor / Project'].nunique()}</div>
                <div class="insight-kpi-label">Unique Vendors</div>
            </div>""", unsafe_allow_html=True)
        with d3:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{merged_df['Base'].dropna().mean():.1f}</div>
                <div class="insight-kpi-label">Overall Avg CVSS</div>
            </div>""", unsafe_allow_html=True)
        with d4:
            ransom_pct = len(merged_df[merged_df["Ransomware Use"] == "Known"]) / len(merged_df) * 100
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{ransom_pct:.0f}%</div>
                <div class="insight-kpi-label">Ransomware Linked</div>
            </div>""", unsafe_allow_html=True)

        # ── Sources ──
        st.markdown("---")
        with st.expander("📚 Sources — Predictive Analysis"):
            sources = [
                ("CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("NIST National Vulnerability Database — CVSS Scores", "https://nvd.nist.gov/"),
                ("scikit-learn LinearRegression Documentation", "https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LinearRegression.html"),
                ("CVSS v3.1 Scoring Standard — FIRST", "https://www.first.org/cvss/specification-document"),
                ("CISA BOD 22-01 — KEV Remediation Requirements", "https://www.cisa.gov/binding-operational-directive-22-01"),
            ]
            for label, url in sources:
                st.markdown(f"""
                <div style="background:rgba(14,165,233,0.05);border:1px solid rgba(56,189,248,0.15);
                            border-left:3px solid #0ea5e9;border-radius:0 10px 10px 0;
                            padding:0.7rem 1rem;margin:0.4rem 0;">
                    <div style="font-family:'Space Mono',monospace;font-size:0.78rem;
                                 color:#38bdf8;margin-bottom:0.2rem;">📄 {label}</div>
                    <a href="{url}" target="_blank"
                       style="font-size:0.74rem;color:#0ea5e9;text-decoration:none;">🔗 {url}</a>
                </div>""", unsafe_allow_html=True)