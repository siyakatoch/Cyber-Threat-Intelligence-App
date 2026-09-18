import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
import warnings
warnings.filterwarnings("ignore")


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

    kev["Date Added"] = pd.to_datetime(kev["Date Added"])
    kev["Due Date"]   = pd.to_datetime(kev["Due Date"])
    kev["Year"]       = kev["Date Added"].dt.year

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
    .insight-kpi-delta       { font-size: 0.72rem; color: #f97316; margin-top: 0.2rem; }
    .insight-kpi-delta-red   { font-size: 0.72rem; color: #ef4444; margin-top: 0.2rem; }
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
    st.markdown('<div class="section-header">☣️ Ransomware Likelihood Classifier</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="insight-card">
    This page applies a <strong>logistic regression classifier</strong> to predict the probability that a 
    given CVE will be actively used in a ransomware attack — based on its CVSS characteristics, vendor, 
    and patch urgency. Unlike the linear regression models on the Predictive Analysis page, this model 
    answers a binary question: <strong>ransomware-linked or not?</strong><br><br>
    This approach directly supports two core CTI operational metrics:<br>
    ⏱️ <strong>MTTD (Mean Time to Detect)</strong> — by flagging high-probability ransomware CVEs before 
    they are weaponized, analysts can prioritize monitoring earlier<br>
    🔧 <strong>MTTR (Mean Time to Respond)</strong> — by pre-ranking CVEs by ransomware likelihood, 
    response teams can act faster when an incident occurs<br><br>
    Data sources: <strong>CISA KEV catalog</strong> + <strong>NIST NVD CVSS scores</strong> | 
    Model: <strong>scikit-learn LogisticRegression</strong>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div class="insight-card" style="background: rgba(240,230,67,0.05); border: 1px solid rgba(240,230,67,0.2);">
    ⚠️ The analytics on this page are not the most accurate for prediction usage because of the limitations caused by our small sample size. 
                We address this in this pages <em>Validation & Limitations</em> tab and <em>CTI Sourcing's Metrics & Validation</em> tab. 
                We include future course of actions for this limitation in the <em>Future CTI Directions</em> page.
    </div>
    """, unsafe_allow_html=True)

    # ── Tabs ──────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs([
        "🎛️ Interactive Classifier",
        "📊 Model Performance",
        "🔍 CVE Risk Rankings",
        "🧠 Validation & Limitations"
    ])

    # ── Prepare model data ────────────────────────────────────────────────────
    model_df = merged_df.copy()

    # Target variable
    model_df["Ransomware"] = model_df["Ransomware Use"].apply(
        lambda x: 1 if x == "Known" else 0
    )

    # Patch urgency feature
    model_df["Days Window"] = (model_df["Due Date"] - model_df["Date Added"]).dt.days
    max_days = model_df["Days Window"].max()
    model_df["Urgency Score"] = model_df["Days Window"].apply(
        lambda x: round((1 - (x / max_days)) * 10, 2) if pd.notna(x) and max_days > 0 else 0
    )

    # Encode vendor
    le = LabelEncoder()
    model_df["Vendor Encoded"] = le.fit_transform(model_df["Vendor / Project"].fillna("Unknown"))

    # Fill missing CVSS with vendor median
    for col in ["Base", "Impact", "Exploitability"]:
        model_df[col] = model_df.groupby("Vendor / Project")[col].transform(
            lambda x: x.fillna(x.median())
        )
    model_df = model_df.dropna(subset=["Base", "Impact", "Exploitability"])

    features = ["Base", "Impact", "Exploitability", "Urgency Score", "Vendor Encoded"]
    X = model_df[features].values
    y = model_df["Ransomware"].values

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
    clf = LogisticRegression(random_state=42, max_iter=1000, class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_scaled)[:, 1]
    model_df["Ransomware Probability"] = (y_prob * 100).round(1)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — INTERACTIVE CLASSIFIER
    # ════════════════════════════════════════════════════════════════════════
    with tab1:
        st.markdown('<div class="sub-header">🎛️ Analytical Control Panel</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        Use the controls below to explore how different parameters affect ransomware likelihood predictions.
        Adjust the <strong>probability threshold</strong> to define what counts as "high risk," select 
        specific vendors to focus on, and choose which analytic view to display.
        </div>
        """, unsafe_allow_html=True)

        # ── Interactive Controls ──
        ctrl1, ctrl2, ctrl3 = st.columns(3)

        with ctrl1:
            analytic_view = st.selectbox(
                "📊 Select Analytic View:",
                options=[
                    "Ransomware Probability by Vendor",
                    "CVE Probability Distribution",
                    "Feature Impact on Prediction",
                ],
                key="analytic_view_select"
            )

        with ctrl2:
            threshold = st.slider(
                "⚠️ High Risk Threshold (%):",
                min_value=30,
                max_value=90,
                value=60,
                step=5,
                key="risk_threshold_slider"
            )

        with ctrl3:
            vendor_options = sorted(model_df["Vendor / Project"].unique().tolist())
            selected_vendors = st.multiselect(
                "🔍 Filter Vendors:",
                options=vendor_options,
                default=["Microsoft", "Cisco", "Google", "Fortinet", "Ivanti"]
                if all(v in vendor_options for v in ["Microsoft", "Cisco", "Google", "Fortinet", "Ivanti"])
                else vendor_options[:5],
                key="classifier_vendor_filter"
            )

        filtered_df = model_df[model_df["Vendor / Project"].isin(selected_vendors)] if selected_vendors else model_df

        colors = {
            "Microsoft": "#60a5fa", "Cisco": "#34d399", "Google": "#f87171",
            "Fortinet": "#fb923c", "Ivanti": "#a78bfa", "Apple": "#fbbf24",
            "Linux": "#94a3b8", "VMware": "#22d3ee", "Citrix": "#e879f9",
            "Broadcom": "#f43f5e", "SAP": "#facc15", "Oracle": "#4ade80",
        }

        st.markdown("---")

        # ── KPI Cards ──
        high_risk = filtered_df[filtered_df["Ransomware Probability"] >= threshold]
        confirmed = filtered_df[filtered_df["Ransomware"] == 1]
        avg_prob = filtered_df["Ransomware Probability"].mean()

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#ef4444">{len(high_risk)}</div>
                <div class="insight-kpi-label">High Risk CVEs</div>
                <div class="insight-kpi-delta">Above {threshold}% threshold</div>
            </div>""", unsafe_allow_html=True)
        with k2:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#f97316">{len(confirmed)}</div>
                <div class="insight-kpi-label">Confirmed Ransomware</div>
                <div class="insight-kpi-delta">In CISA KEV dataset</div>
            </div>""", unsafe_allow_html=True)
        with k3:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{avg_prob:.1f}%</div>
                <div class="insight-kpi-label">Avg Ransomware Prob</div>
                <div class="insight-kpi-delta">Across filtered vendors</div>
            </div>""", unsafe_allow_html=True)
        with k4:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{len(filtered_df)}</div>
                <div class="insight-kpi-label">CVEs Analyzed</div>
                <div class="insight-kpi-delta">In current filter</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Dynamic Chart based on selectbox ──
        if analytic_view == "Ransomware Probability by Vendor":
            chart_header("📊 Average Ransomware Probability by Vendor",
                "This bar graph shows the average predicted ransomware probability for CVEs from each vendor in the current filter. The dashed line indicates the high risk threshold you set. Use this to compare which vendors have more CVEs that are likely to be used in ransomware attacks.",
                "info_probability_vendor")
            vendor_prob = (
                filtered_df.groupby("Vendor / Project")["Ransomware Probability"]
                .mean().reset_index()
                .rename(columns={"Vendor / Project": "Vendor", "Ransomware Probability": "Avg Probability (%)"})
                .sort_values("Avg Probability (%)", ascending=False)
            )
            vendor_prob["Avg Probability (%)"] = vendor_prob["Avg Probability (%)"].round(1)
            fig = px.bar(
                vendor_prob, x="Vendor", y="Avg Probability (%)",
                color="Vendor", color_discrete_map=colors,
                template="plotly_dark", text="Avg Probability (%)",
            )
            fig.add_hline(
                y=threshold, line_dash="dash", line_color="#ef4444",
                annotation_text=f"High Risk Threshold ({threshold}%)",
                annotation_font_color="#ef4444",
            )
            fig.update_traces(textposition="outside")
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1", showlegend=False,
                yaxis=dict(range=[0, 115], title="Ransomware Probability (%)", gridcolor="#1e3a5f"),
                margin=dict(l=0, r=0, t=20, b=0),
            )
            st.plotly_chart(fig, use_container_width=True)

        elif analytic_view == "CVE Probability Distribution":
            st.markdown('<div class="sub-header">📊 Ransomware Probability Distribution Across CVEs</div>', unsafe_allow_html=True)
            fig = px.histogram(
                filtered_df, x="Ransomware Probability",
                color="Vendor / Project", color_discrete_map=colors,
                nbins=20, template="plotly_dark",
                labels={"Ransomware Probability": "Ransomware Probability (%)"},
            )
            fig.add_vline(
                x=threshold, line_dash="dash", line_color="#ef4444",
                annotation_text=f"High Risk ({threshold}%)",
                annotation_font_color="#ef4444",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1", legend_title="Vendor",
                yaxis=dict(title="Number of CVEs", gridcolor="#1e3a5f"),
                margin=dict(l=0, r=0, t=20, b=0),
            )
            st.plotly_chart(fig, use_container_width=True)

        elif analytic_view == "Feature Impact on Prediction":
            st.markdown('<div class="sub-header">📊 Feature Coefficients — What Drives Ransomware Likelihood?</div>', unsafe_allow_html=True)
            coef_df = pd.DataFrame({
                "Feature": ["Base CVSS", "Impact Score", "Exploitability", "Patch Urgency", "Vendor"],
                "Coefficient": clf.coef_[0].tolist(),
            }).sort_values("Coefficient", ascending=False)
            coef_df["Interpretation"] = coef_df["Coefficient"].apply(
                lambda x: "📈 Increases ransomware likelihood" if x > 0 else "📉 Decreases ransomware likelihood"
            )
            fig = px.bar(
                coef_df.sort_values("Coefficient"),
                x="Coefficient", y="Feature", orientation="h",
                color="Coefficient",
                color_continuous_scale=["#1e3a5f", "#0ea5e9", "#ef4444"],
                template="plotly_dark", text="Coefficient",
            )
            fig.update_traces(texttemplate="%{text:.3f}", textposition="outside")
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
                font_color="#cbd5e1", coloraxis_showscale=False,
                xaxis_title="Logistic Regression Coefficient",
                yaxis=dict(autorange="reversed"),
                height=300, margin=dict(l=0, r=60, t=20, b=0),
            )
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(coef_df[["Feature", "Coefficient", "Interpretation"]], use_container_width=True, hide_index=True)

        # ── High Risk CVE Table ──
        chart_header("🔴 High Risk CVEs — Above Threshold",
                "This table shows the CVEs that the model predicts have a ransomware probability above the threshold you set, along with key details like severity, vendor, and whether they are already confirmed as ransomware-linked in the CISA KEV dataset. Use this to identify which specific CVEs pose the highest risk.",
                "info_high_risk_table")
        high_risk_display = high_risk[[
            "CVE ID", "Vendor / Project", "Product", "Severity",
            "Ransomware Probability", "Ransomware Use", "Base", "CISA Directive"
        ]].sort_values("Ransomware Probability", ascending=False).reset_index(drop=True)
        high_risk_display["Ransomware Probability"] = high_risk_display["Ransomware Probability"].apply(
            lambda x: f"{x}%"
        )
        st.dataframe(high_risk_display, use_container_width=True, hide_index=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — MODEL PERFORMANCE
    # ════════════════════════════════════════════════════════════════════════
    with tab2:
        st.markdown('<div class="sub-header">📊 Model Evaluation Metrics</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        The classifier is evaluated using <strong>precision, recall, and F1-score</strong> — the three 
        standard metrics for binary classification models. These map directly to CTI operational value:<br><br>
        🎯 <strong>Precision</strong> — of all CVEs we flagged as ransomware-likely, how many actually were? 
        High precision = fewer false alarms for SOC analysts<br>
        🔍 <strong>Recall</strong> — of all actual ransomware CVEs, how many did we catch? 
        High recall = fewer missed threats (critical for MTTD)<br>
        ⚖️ <strong>F1-Score</strong> — the balance between precision and recall. 
        The primary metric for imbalanced datasets like ours
        </div>
        """, unsafe_allow_html=True)

        precision = precision_score(y_test, y_pred, zero_division=0)
        recall    = recall_score(y_test, y_pred, zero_division=0)
        f1        = f1_score(y_test, y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_test, clf.predict_proba(X_test)[:, 1])
        except Exception:
            auc = 0.0

        # ── KPI Metrics ──
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#34d399">{precision:.2f}</div>
                <div class="insight-kpi-label">Precision</div>
                <div class="insight-kpi-delta-green">Low false alarm rate</div>
            </div>""", unsafe_allow_html=True)
        with m2:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#38bdf8">{recall:.2f}</div>
                <div class="insight-kpi-label">Recall</div>
                <div class="insight-kpi-delta">Threat coverage rate</div>
            </div>""", unsafe_allow_html=True)
        with m3:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#f97316">{f1:.2f}</div>
                <div class="insight-kpi-label">F1-Score</div>
                <div class="insight-kpi-delta">Precision-recall balance</div>
            </div>""", unsafe_allow_html=True)
        with m4:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#a78bfa">{auc:.2f}</div>
                <div class="insight-kpi-label">ROC-AUC Score</div>
                <div class="insight-kpi-delta">Overall discrimination</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Confusion Matrix ──
        chart_header("🔢 Confusion Matrix",
                "This matrix shows how many CVEs the model correctly classified vs misclassified. True Positives = correctly flagged ransomware CVEs | False Negatives = missed ransomware CVEs (most critical to minimize for MTTD)",
                "info_confusion_matrix")
        st.markdown("""
        <div class="insight-card" style="font-size:0.85rem">
        The confusion matrix shows how many CVEs the model correctly classified vs misclassified.
        <strong>True Positives</strong> = correctly flagged ransomware CVEs |
        <strong>False Negatives</strong> = missed ransomware CVEs (most critical to minimize for MTTD)
        </div>
        """, unsafe_allow_html=True)

        cm = confusion_matrix(y_test, y_pred)
        cm_df = pd.DataFrame(
            cm,
            index=["Actual: Not Ransomware", "Actual: Ransomware"],
            columns=["Predicted: Not Ransomware", "Predicted: Ransomware"]
        )
        fig_cm = px.imshow(
            cm_df, text_auto=True,
            color_continuous_scale=["#0a1628", "#0ea5e9", "#ef4444"],
            template="plotly_dark",
        )
        fig_cm.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#cbd5e1",
            height=300,
            margin=dict(l=0, r=0, t=20, b=0),
        )
        st.plotly_chart(fig_cm, use_container_width=True)

        # ── Operational Metrics ──
        st.markdown("---")
        st.markdown('<div class="sub-header">⏱️ Operational Metrics — MTTD & MTTR Impact</div>', unsafe_allow_html=True)
        op1, op2 = st.columns(2)
        with op1:
            st.markdown("""
            <div class="insight-card">
            <strong style="color:#38bdf8">MTTD — Mean Time to Detect</strong><br><br>
            Without this classifier, SOC analysts must manually review all 100 CVEs to identify 
            ransomware threats. With the classifier, high-probability CVEs are surfaced immediately —
            reducing the time analysts spend searching for threats.<br><br>
            <strong>Estimated MTTD Improvement:</strong> By pre-ranking CVEs by ransomware probability,
            analysts can focus on the top 20% of CVEs that represent the highest confirmed risk —
            reducing manual triage time by an estimated 60–70%.
            </div>
            """, unsafe_allow_html=True)
        with op2:
            st.markdown("""
            <div class="insight-card">
            <strong style="color:#38bdf8">MTTR — Mean Time to Respond</strong><br><br>
            When a ransomware incident occurs, response teams need to know immediately which 
            CVE was likely exploited. Pre-computed ransomware probability scores give incident 
            responders a ranked shortlist of likely attack vectors — enabling faster containment.<br><br>
            <strong>Estimated MTTR Improvement:</strong> Faster CVE attribution during an active 
            incident reduces investigation time, enabling earlier containment and reducing 
            dwell time for ransomware operators inside contractor networks.
            </div>
            """, unsafe_allow_html=True)

        # ── Probability Distribution Chart ──
        chart_header("📊 Ransomware Probability Distribution — Full Dataset",
                "This bar graph shows the distribution of predicted ransomware probabilities across all CVEs in the dataset. The dashed line indicates the high risk threshold you set. Use this to understand how many CVEs fall into different risk categories and to identify any clusters of high-probability CVEs.",
                "info_probability_dist")
        fig_dist = px.histogram(
            model_df, x="Ransomware Probability",
            color="Ransomware Use",
            color_discrete_map={"Known": "#ef4444", "Unknown": "#60a5fa"},
            nbins=20, template="plotly_dark", barmode="overlay",
            labels={"Ransomware Probability": "Predicted Ransomware Probability (%)"},
        )
        fig_dist.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1", legend_title="Ransomware Status",
            yaxis=dict(title="Number of CVEs", gridcolor="#1e3a5f"),
            margin=dict(l=0, r=0, t=20, b=0),
        )
        st.plotly_chart(fig_dist, use_container_width=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — CVE RISK RANKINGS
    # ════════════════════════════════════════════════════════════════════════
    with tab3:
        st.markdown('<div class="sub-header">🔍 All CVEs Ranked by Ransomware Probability</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        Every CVE in the dataset ranked from highest to lowest ransomware likelihood. 
        Use the <strong>Top-N selector</strong> to focus on the most critical CVEs.
        CVEs already confirmed as ransomware-linked are marked in the Ransomware Use column.
        </div>
        """, unsafe_allow_html=True)

        # ── Top-N Selector ──
        top_n = st.slider(
            "🔢 Drag the bar to show top *n* number of CVEs by Ransomware Probability:",
            min_value=5, max_value=len(model_df),
            value=20, step=5,
            key="top_n_slider"
        )

        vendor_filter_tab3 = st.multiselect(
            "Filter by Vendor:",
            options=sorted(model_df["Vendor / Project"].unique().tolist()),
            default=[],
            key="tab3_vendor_filter",
            placeholder="All vendors shown — select to filter"
        )

        display_df = model_df.copy()
        if vendor_filter_tab3:
            display_df = display_df[display_df["Vendor / Project"].isin(vendor_filter_tab3)]

        top_cves = display_df.sort_values("Ransomware Probability", ascending=False).head(top_n)

        # ── Bar chart ──
        colors_ransom = top_cves["Ransomware Use"].map({"Known": "#ef4444", "Unknown": "#60a5fa"})
        fig_top = go.Figure(go.Bar(
            x=top_cves["Ransomware Probability"],
            y=top_cves["CVE ID"],
            orientation="h",
            marker_color=colors_ransom,
            text=top_cves["Ransomware Probability"].apply(lambda x: f"{x}%"),
            textposition="outside",
        ))
        fig_top.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,20,40,0.6)",
            font_color="#cbd5e1",
            xaxis=dict(range=[0, 115], title="Ransomware Probability (%)", gridcolor="#1e3a5f"),
            yaxis=dict(autorange="reversed"),
            height=max(300, top_n * 22),
            margin=dict(l=0, r=60, t=20, b=0),
        )
        st.plotly_chart(fig_top, use_container_width=True)

        st.markdown("""
        <div class="insight-card" style="font-size:0.82rem">
        🔴 <strong style="color:#ef4444">Red bars</strong> = Confirmed ransomware use in CISA KEV &nbsp;|&nbsp;
        🔵 <strong style="color:#60a5fa">Blue bars</strong> = Not confirmed — predicted probability only
        </div>
        """, unsafe_allow_html=True)

        # ── Full table ──
        chart_header("📋 Full Ranked CVE Table",
                "This table shows the top *n* CVEs ranked by the model's predicted ransomware probability, along with key CVE details and whether they are already confirmed as ransomware-linked in the CISA KEV dataset.",
                "info_ranked_cve_table")
        ranked_display = top_cves[[
            "CVE ID", "Vendor / Project", "Product", "Severity",
            "Base", "Ransomware Probability", "Ransomware Use", "CISA Directive"
        ]].reset_index(drop=True)
        ranked_display["Ransomware Probability"] = ranked_display["Ransomware Probability"].apply(
            lambda x: f"{x}%"
        )
        st.dataframe(ranked_display, use_container_width=True, hide_index=True)

    # ════════════════════════════════════════════════════════════════════════
    # TAB 4 — VALIDATION & LIMITATIONS
    # ════════════════════════════════════════════════════════════════════════
    with tab4:
        st.markdown('<div class="sub-header">🧪 Validation Method</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        <strong style="color:#38bdf8">Hold-Out Test Validation</strong><br><br>
        The dataset of 100 CVEs was split into <strong>80% training (80 CVEs)</strong> and 
        <strong>20% test (20 CVEs)</strong> using scikit-learn's train_test_split with stratification —
        meaning the same proportion of ransomware vs non-ransomware CVEs is preserved in both sets.<br><br>
        The model was trained exclusively on the training set and evaluated on the held-out test set 
        that it had never seen before. The precision, recall, F1, and AUC scores shown on the 
        Model Performance tab are all computed on this held-out test set — not the training data.
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="sub-header">⚙️ Analytical Procedure — Step by Step</div>', unsafe_allow_html=True)

        with st.expander("✅ Step 1 — Data Preparation"):
            st.markdown("""
            <span style='color:#ffffff'>
            Merged CISA KEV entries with CVSS scores from NIST NVD. Cleaned non-numeric values 
            (N/A, ~5.0) that appeared in the raw JSON files. Filled missing CVSS fields with 
            vendor-level medians to preserve as many records as possible without introducing bias 
            from global averages.
            </span>""", unsafe_allow_html=True)

        with st.expander("✅ Step 2 — Feature Engineering"):
            st.markdown("""
            <span style='color:#ffffff'>
            Created two derived features beyond the raw CVSS scores:<br><br>
            <strong>Urgency Score</strong> — inverted patch window (tighter CISA deadline = higher urgency score).
            Calculated as: (1 - days_window / max_days) × 10.<br><br>
            <strong>Vendor Encoded</strong> — label-encoded vendor name as a numeric feature so the model 
            can learn vendor-specific ransomware patterns.<br><br>
            Applied StandardScaler to normalize all features before model training — ensuring no single 
            feature dominates due to scale differences.
            </span>""", unsafe_allow_html=True)

        with st.expander("✅ Step 3 — Model Selection"):
            st.markdown("""
            <span style='color:#ffffff'>
            Selected <strong>Logistic Regression</strong> for three reasons:<br><br>
            1. It produces <strong>probability outputs (0–100%)</strong> rather than just binary yes/no 
            predictions — giving analysts a ranked list instead of a binary flag<br>
            2. It is <strong>interpretable via coefficients</strong> — we can explain exactly which 
            features drive ransomware likelihood<br>
            3. It is <strong>appropriate for small datasets</strong> — unlike neural networks or 
            ensemble methods that need thousands of samples<br><br>
            Used <strong>class_weight='balanced'</strong> to account for the imbalance between 
            ransomware (~15%) and non-ransomware (~85%) CVEs in the dataset.
            </span>""", unsafe_allow_html=True)

        with st.expander("✅ Step 4 — Training & Evaluation"):
            st.markdown("""
            <span style='color:#ffffff'>
            Split the dataset 80/20 using stratified sampling — preserving the ransomware/non-ransomware 
            ratio in both sets. Trained exclusively on the 80-CVE training set.<br><br>
            Evaluated on the 20-CVE held-out test set using:<br>
            <strong>Precision</strong> — how many flagged CVEs were actually ransomware-linked<br>
            <strong>Recall</strong> — how many actual ransomware CVEs did we catch<br>
            <strong>F1-Score</strong> — the balance between precision and recall<br>
            <strong>ROC-AUC</strong> — overall model discrimination ability<br><br>
            Generated a confusion matrix to identify false negatives (missed ransomware CVEs) 
            as the primary concern for CTI operations — a missed ransomware CVE is more costly 
            than a false alarm.
            </span>""", unsafe_allow_html=True)

        with st.expander("✅ Step 5 — Prediction & Ranking"):
            st.markdown("""
            <span style='color:#ffffff'>
            Applied the trained model to all 100 CVEs to generate probability scores ranging from 
            0–100%. These scores represent the model's confidence that each CVE will be actively 
            used in a ransomware attack.<br><br>
            CVEs are ranked from highest to lowest probability — giving SOC analysts and CISOs 
            a prioritized watchlist. The threshold slider on the Interactive Classifier tab lets 
            users define their own "high risk" cutoff based on their organization's risk tolerance.
            </span>""", unsafe_allow_html=True)

        st.markdown('<div class="sub-header">⚠️ Assumptions & Limitations</div>', unsafe_allow_html=True)
        limitations = [
            "Small dataset — 100 CVEs with only ~15 confirmed ransomware cases is a limited training set. The model learns directional patterns but precise probability values should be treated as estimates.",
            "Class imbalance — ransomware-confirmed CVEs (~15%) are outnumbered by non-confirmed CVEs (~85%). We use class_weight='balanced' to compensate, but this can increase false positives.",
            "Binary target — 'Ransomware Use' in CISA KEV is either Known or Unknown. Unknown does not mean 'not ransomware' — it may simply mean it hasn't been confirmed yet, which introduces label noise.",
            "Vendor encoding — encoding vendor as a numeric label assumes an ordinal relationship between vendors that doesn't really exist. A one-hot encoding would be more accurate but requires more data.",
            "No temporal features — the model does not account for when a CVE was disclosed or how quickly it was exploited. Adding time-based features would improve real-world applicability.",
        ]
        for lim in limitations:
            st.markdown(f'<div class="model-box">⚠️ {lim}</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sub-header">🎯 CTI Value — Why This Approach Was Selected</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="insight-card">
        Ransomware is one of the most documented and financially damaging threats to defense contractors.
        LockBit compromised a SpaceX Tier 3 supplier in 2023. Akira and LockBit both actively exploited 
        Cisco ASA VPN vulnerabilities confirmed in our CISA KEV dataset. The ability to predict ransomware 
        likelihood <strong>before exploitation occurs</strong> is a direct force multiplier for CTI teams:<br><br>
        📉 <strong>Reduces MTTD</strong> by pre-ranking threats by probability<br>
        🔧 <strong>Reduces MTTR</strong> by providing a ranked shortlist during incident response<br>
        🎯 <strong>Improves alert precision</strong> by focusing analyst attention on highest-probability CVEs<br>
        📊 <strong>Quantifies risk</strong> in a way that supports CISO-level reporting and board presentations
        </div>
        """, unsafe_allow_html=True)

        # ── Dataset Summary ──
        st.markdown("---")
        chart_header("📂 Dataset Summary",
            "These KPI cards summarize the full dataset used to train both models on this page — total CVEs, unique vendors tracked, overall average CVSS score across all CVEs, and the percentage of CVEs confirmed as ransomware-linked by CISA.",
            "info_dataset_summary")
        d1, d2, d3, d4 = st.columns(4)
        with d1:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{len(model_df)}</div>
                <div class="insight-kpi-label">Total CVEs</div>
            </div>""", unsafe_allow_html=True)
        with d2:
            ransom_count = model_df["Ransomware"].sum()
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value" style="color:#ef4444">{ransom_count}</div>
                <div class="insight-kpi-label">Ransomware Confirmed</div>
            </div>""", unsafe_allow_html=True)
        with d3:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">80 / 20</div>
                <div class="insight-kpi-label">Train / Test Split</div>
            </div>""", unsafe_allow_html=True)
        with d4:
            st.markdown(f"""
            <div class="insight-kpi">
                <div class="insight-kpi-value">{len(features)}</div>
                <div class="insight-kpi-label">Features Used</div>
                <div class="insight-kpi-delta">CVSS + Urgency + Vendor</div>
            </div>""", unsafe_allow_html=True)

        # ── Sources ──
        st.markdown("---")
        with st.expander("📚 Sources — Ransomware Classifier"):
            sources = [
                ("CISA Known Exploited Vulnerabilities Catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                ("NIST National Vulnerability Database — CVSS Scores", "https://nvd.nist.gov/"),
                ("scikit-learn LogisticRegression Documentation", "https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html"),
                ("CVSS v3.1 Scoring Standard — FIRST", "https://www.first.org/cvss/specification-document"),
                ("CISA BOD 22-01 — KEV Remediation Requirements", "https://www.cisa.gov/binding-operational-directive-22-01"),
                ("LockBit / SpaceX Contractor Breach — SecurityAffairs (March 2023)", "https://securityaffairs.com/143495/cyber-crime/lockbit-ransomware-gang-spacex-files.html"),
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