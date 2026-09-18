# Cyber Threat Intelligence App

## Problem Statement

Cyber threat intelligence is difficult to obtain for vendors operating within the U.S. defense supply chain. While large prime contractors and government agencies may have dedicated security teams, the vendors and suppliers that support them — software providers, hardware manufacturers, logistics firms, and specialized consultants — often lack access to intelligence that reflects their specific risk exposure.

These vendors are high-value targets precisely because of their proximity to sensitive defense operations, yet publicly available reporting rarely addresses their unique threat landscape. This platform addresses that gap by aggregating and presenting open-source cyber threat intelligence (CTI) tailored specifically to vendors and suppliers in the U.S. defense industrial base.

Rather than requiring analysts or stakeholders to manually sift through disparate reports, this app centralizes, structures, and visualizes that intelligence in one place.

---

## Sector Focus

This platform targets **vendors and suppliers to U.S. defense contractors**, including:

- **Software and IT service providers** supporting defense programs
- **Hardware and component manufacturers** in the defense supply chain
- **Logistics and facilities management firms** with defense contracts
- **Specialized consultants and subcontractors** working on sensitive programs

These organizations face a distinct threat environment — adversaries frequently target vendors as a stepping stone to reach prime contractors and the government agencies they serve — that generic cybersecurity dashboards do not adequately capture.

---

## Data Sources

All data used in this platform is **OSINT (Open-Source Intelligence)** — publicly available and freely accessible. Sources include:

| Source | Description |
|--------|-------------|
| [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 100 defense/government-curated CVEs with severity, ransomware flags, and CISA directives |
| [NIST National Vulnerability Database](https://nvd.nist.gov) | CVSS v3.1 Base, Impact, and Exploitability scores enriching the KEV dataset |
| [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | Official U.S. government advisories on active threats and nation-state activity |
| [MITRE ATT&CK](https://attack.mitre.org) | Threat actor profiles, TTP mappings, and group attribution used in diamond models |
| [CSIS Significant Cyber Incidents](https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents) | Curated timeline of major state-sponsored and criminal cyber incidents |

Full source citations are listed on each page of the application.

---

## App Pages

| Page | What It Shows |
|------|---------------|
| **Introduction** | Frames the problem, introduces the platform, and provides context on the defense supply chain's unique cybersecurity challenges — including why vendors are disproportionately targeted. |
| **Stakeholders** | Defines the personas this platform serves — vendor security teams, compliance officers, and executive leadership — who they are, what decisions they make, and why CTI matters to them. Seperate tab contains Role-Based Views for each stakeholder. |
| **Threat Model** | Presents the CTI use case for defense vendors and maps out the threat model, explaining what adversaries want from supply chain targets, how they operate, and what's at stake for the broader defense ecosystem. |
| **Trends & Assets** | Split into two sections: (1) **Threat Trends** — common attack patterns targeting vendors, recent supply chain incidents, active threat actors, and exploited technologies; (2) **Critical Assets** — the systems, data, and infrastructure most at risk for defense-sector vendors. |
| **Diamond Models** | Applies the Diamond Model framework to two real-world campaigns active through 2026: APT29's cloud/identity espionage campaign and Volt Typhoon's critical infrastructure pre-positioning. Each model maps adversary, capability, infrastructure, and victim nodes with current TTPs and sources. |
| **Dashboard** | Interactive CISA KEV analysis dashboard with filters by severity, vendor, ransomware use, and CISA directive. Includes live KPIs, six charts, and three filterable tables. |
| **Triage Dashboard** | 100 vulnerabilities curated from CISA's Known Exploited Vulnerabilities catalog — prioritized by Emergency Directives, active exploitation, and DoD/federal prevalence. Provides filter and download options to find and save specific CVEs. |
| **Intelligence Buy-In** | Makes the business case for CTI investment: breach cost data, a phased CTI roadmap, and ROI modeling tailored to vendor organizations operating under defense contracts. |
| **Linear Regression Analysis** | Applies linear regression models to our CISA KEV and CVSS data to predict future potential exploitations for each vendor and analyze if their CVSS scores are improving or not. |
| **Ransomeware Prediction** | This page applies a logistic regression classifier to predict the probability that a given CVE will be actively used in a ransomware attack — based on its CVSS characteristics, vendor, and patch urgency. |
| **Intelligence & Dissemination** | This page translates raw CISA KEV and CVSS data into actionable operational intelligence for defense contractors like Lockheed Martin, Boeing, and Leidos. It covers course of actions and dissemination strategy. |
| **CTI Sourcing** | Comprehensive justification for CISA KEV and NIST NVD as primary data sources — covering value, data volume and limitations, collection strategy, and industry adoption. |
| **Ethics & Security Practices** | This page covers ethical concerns regarding data usage and gathering as well as security practices we use to ensure platform security and abuse. |
| **Key Insights** | This page contains insights into our data and what influences it; such as common infrastructure weaknesses, emerging threats, threat actors, and TTPs. |
| **Future CTI Directions** | The current platform delivers a strong foundation for defense vendor CTI analysis — but three high-impact development directions would transform it from a static intelligence dashboard into a live, automated, analyst-grade CTI operations platform. Each direction is grounded in real industry gaps identified through this project's research and directly extends the work completed in Milestones 1–3.|
| **About Us & Checklist** | Documents individual team contributions and tracks project milestone requirements. |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| Framework | Streamlit |
| Data Handling | Pandas |
| Visualizations | Plotly |
| Data Format | JSON |
| Data Analytics | scikit-learn |

---

## Project Structure

```
Cyber-Threat-Intelligence-App/
│
├── app.py                        # Main entry point — routing and navbar
│
├── data/
│   ├── Defense_KEV_Entries.json                  # 100 curated CISA KEV entries (defense/gov-relevant)
│   ├── Data_with_Scores.json                     # CVSS v3.1 scores from NIST NVD, merged by CVE ID
│   └── CISA_KEV_Defense_TI_Report_Enriched.json  # 100 curated CISA KEV entries (defense/gov-relevant) w/ descriptions
│
├── pages/
│   ├── [python file]             # [Homepage Title Square]
│   ├── background.py             # Introduction & Background
│   ├── stakeholders.py           # Stakeholders & User Stories
│   ├── cti_use_case.py           # CTI Use Case / Threat Model
│   ├── threat_trends.py          # Threat Trends & Critical Assets
│   ├── diamond_models.py         # Diamond Models (APT29, LockBit 3.0)
│   ├── cti_dashboard.py          # Interactive KEV Dashboard
│   ├── intelligence_buy_in.py    # Intelligence Buy-In & ROI
│   ├── analytics.py              # Data Analysis (Analytical Approach #1)
│   ├── ransomware_analysis.py    # Data Analysis (Analytical Approach #2)
│   ├── cti_sourcing.py           # CTI Data Source Justification & Collection Strategies; Validation Analysis
│   ├── ethics_security.py        # Ethics & Security Practices
│   ├── key_insights.py           # Key Insights
│   └── about_us.py               # About Us (Roles) & Checklist
│   └── future_cti.py             # Future CTI Directions
│   └── operational_intel.py      # Intelligence & Dissemination
│   └── triage_dashboard.py       # Triage Dashboard
│
└── static/
    └── hero.jpg                  # Homepage hero background image
```

---

## Setup & Installation 

### Step 1 — Clone the Repository 

```bash
cd Cyber-Threat-Intelligence-App
```

### Step 2 — Install Dependencies

```bash
pip install streamlit
pip install plotly
pip install pandas
pip install scikit-learn
```

### Step 3 — Run the App

```bash
streamlit run app.py
```

Streamlit will open the app automatically in your browser. If it doesn't, navigate to `http://localhost:8501`.

> These instructions work in **GitHub Codespaces**, Mac, Windows, and Linux terminals.

---

## How to Reproduce the Analysis

The dashboard and data explorer are built on two JSON datasets derived from public government sources. To reproduce the full pipeline:

**1. CISA KEV Dataset (`Defense_KEV_Entries.json`)**
- Source: [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- The full catalog was filtered to 100 entries using three criteria:
  - Governing directive is BOD 22-01 or an Emergency Directive (ED 25-02, ED 25-03, ED 26-03)
  - Active exploitation confirmed in DoD or FCEB environments
  - Vendor products prevalent in defense sector IT stacks (Windows, Cisco IOS, Fortinet FortiOS, Ivanti Connect Secure, VMware ESXi)
- Fields retained: CVE ID, Vendor/Project, Product, Vulnerability Name, Severity, Date Added, Due Date, Ransomware Use, CWEs, CISA Directive, Defense Relevance

**2. CVSS Scores Dataset (`Data_with_Scores.json`)**
- Source: [NIST NVD REST API](https://services.nvd.nist.gov/rest/json/cves/2.0)
- CVSS v3.1 Base Score, Impact Score, and Exploitability Score were retrieved for each of the 100 KEV entries via CVE ID lookup
- Results were stored separately and merged with `Defense_KEV_Entries.json` on CVE ID in the dashboard at load time
- 99 of 100 entries have available scores; 1 entry was pending NVD analysis at time of collection

**3. CISA KEV Dataset with Descriptions (`Defense_KEV_Entries.json`)**
- Source: [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- The full catalog was filtered to 100 entries using three criteria:
  - Governing directive is BOD 22-01 or an Emergency Directive (ED 25-02, ED 25-03, ED 26-03)
  - Active exploitation confirmed in DoD or FCEB environments
  - Vendor products prevalent in defense sector IT stacks (Windows, Cisco IOS, Fortinet FortiOS, Ivanti Connect Secure, VMware ESXi)
- Fields retained: CVE ID, Vendor/Project, Product, Vulnerability Name, Severity, Date Added, Due Date, Ransomware Use, CWEs, CISA Directive, Defense Relevance

**4. Running the Dashboard**
- Navigate to the **Dashboard** page in the app
- Use the Severity, Vendor, Ransomware Use, and CISA Directive filters to explore the dataset
- All charts, KPIs, and tables update dynamically based on filter selections

---

## Current Functionality & Status

All pages are fully operational.

| Milestone Requirement | Page in App | Status |
|--------|--------|--------|
| Milestone 1 | | |
| Introduction & Industry Background | Introduction |✅ Complete |
| Defined Stakeholders and User Stories | Stakeholders | ✅ Complete |
| Threat-Model-Backed Design/CTI Use Case| Threat Model | ✅ Complete |
| Relevant Threat Trends and Critical Asset Identification | Trends & Assets | ✅ Complete |
| Diamond Models | Diamond Models | ✅ Complete |
| Dashboard Starter | Dashboard |✅ Complete |
| Intelligence Buy-In | Intelligence Buy-In | ✅ Complete |
| Milestone 2 | | |
| CTI Data Source Identification and Justification | CTI Sourcing | ✅ Complete |
| Collection Strategies and Data Summary | CTI Sourcing | ✅ Complete |
| Dynamic Data Explorer | Dashboard, Linear Regression Analysis, Ransomeware Prediction | ✅ Complete |
| Minimum Data Expectations | CTI Sourcing | ✅ Complete |
| Reproducibility Requirements | README.md | ✅ Complete |
| Ethics and Data Governance | Ethics & Security Practices  | ✅ Complete |
| Security-Aware Development Practices | Ethics & Security Practices |  ✅ Complete |
| Group Roles and Signatures | About Us & Checklist | ✅ Complete |
| Milestone 3 | | |
| Analytical Approaches and Justification | Linear Regression Analysis, Ransomeware Prediction | ✅ Complete |
| Interactive Analytics Panel | Dashboard, Linear Regression Analysis, Ransomeware Prediction | ✅ Complete |
| Operational Metrics | Linear Regression Analysis, Ransomeware Prediction | ✅ Complete |
| Validation and Error Analysis | CTI Sourcing | ✅ Complete |
| Preliminary Visualizations | Dashboard | ✅ Complete |
| Key Insights and Intelligence Summary | Key Insights | ✅ Complete |
| Milestone 4 | | |
| Key Insights and Intelligence Summary | Key Insights | ✅ Complete |
| Operational Intelligence and Dissemination | Intelligence & Dissemination| ✅ Complete |
| Operational Triage Dashboard | Triage Dashboard | ✅ Complete |
| Role-Based Views | Stakeholders | ✅ Complete |
| Actionable Outputs | Triage Dashboard, Intelligence & Dissemination| ✅ Complete |
| Future CTI Platform Directions | Future CTI Directions | ✅ Complete |

The app is updated with each milestone submission, so the version in this repository always reflects the project's current state.