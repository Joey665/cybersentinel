import streamlit as st
import requests
import plotly.express as px
import pandas as pd

# ----------------------------------------------------------------------------
# Page configuration
# ----------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberSentinel",
    page_icon="🛡️",
    layout="wide"
)

# ----------------------------------------------------------------------------
# Custom CSS - Enterprise SOC dark theme
# ----------------------------------------------------------------------------
st.markdown("""
<style>
    /* Overall app background */
    .stApp {
        background-color: #0E1117;
        color: #E6E6E6;
        font-family: 'Consolas', 'Courier New', monospace;
    }

    /* Sidebar / block containers */
    section[data-testid="stSidebar"] {
        background-color: #0A0C10;
    }

    /* Headings */
    h1, h2, h3, h4 {
        font-family: 'Consolas', 'Courier New', monospace;
        letter-spacing: 0.5px;
    }

    /* Text area styling */
    .stTextArea textarea {
        background-color: #161A23;
        color: #00FFC2;
        border: 1px solid #2A2F3A;
        font-family: 'Consolas', 'Courier New', monospace;
    }

    /* Buttons */
    .stButton > button {
        background-color: #111827;
        color: #00FFC2;
        border: 1px solid #00FFC2;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s ease-in-out;
        height: 3em;
        width: 100%;
    }
    .stButton > button:hover {
        background-color: #00FFC2;
        color: #0E1117;
        box-shadow: 0 0 12px #00FFC2;
    }

    /* Metric containers - glowing border effect */
    div[data-testid="stMetric"] {
        background-color: #12151C;
        border: 1px solid #1F6FEB;
        border-radius: 10px;
        padding: 15px 10px;
        box-shadow: 0 0 10px rgba(0, 255, 194, 0.25);
    }
    div[data-testid="stMetric"] label {
        color: #8B949E !important;
        font-family: 'Consolas', 'Courier New', monospace;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #00FFC2;
        font-weight: 700;
    }

    /* Critical metric variant (applied via wrapper class below) */
    .critical-metric div[data-testid="stMetric"] {
        border: 1px solid #FF3860;
        box-shadow: 0 0 14px rgba(255, 56, 96, 0.45);
    }
    .critical-metric div[data-testid="stMetricValue"] {
        color: #FF3860 !important;
    }

    .safe-metric div[data-testid="stMetric"] {
        border: 1px solid #00FFC2;
        box-shadow: 0 0 14px rgba(0, 255, 194, 0.35);
    }

    /* Expander */
    .streamlit-expanderHeader {
        background-color: #161A23;
        color: #FF3860;
        font-weight: 700;
        border-radius: 6px;
    }

    hr {
        border-color: #2A2F3A;
    }
</style>
""", unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------------
st.markdown(
    "<h1 style='text-align: center; color: #00FFC2;'>🛡️ CyberSentinel: Supply Chain Threat Intel</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align: center; color: #8B949E;'>Real-time NPM dependency risk scanning & threat intelligence</p>",
    unsafe_allow_html=True
)
st.markdown("---")

# ----------------------------------------------------------------------------
# Input section - side-by-side layout
# ----------------------------------------------------------------------------
st.subheader("📦 Enter NPM Dependencies")
st.caption("Format: one package per line as `package_name==version` (e.g., `lodash==4.17.15`)")

input_col, button_col = st.columns([3, 1])

with input_col:
    packages_input = st.text_area(
        "Packages",
        height=150,
        placeholder="lodash==4.17.15\nexpress==4.18.2\nreact==18.2.0",
        label_visibility="collapsed"
    )

with button_col:
    # Vertical spacer to align button with text area
    st.write("")
    scan_clicked = st.button("🔍 Scan Dependencies", type="primary", use_container_width=True)

st.markdown("---")

# ----------------------------------------------------------------------------
# Scan logic
# ----------------------------------------------------------------------------
if scan_clicked:
    if not packages_input.strip():
        st.warning("Please enter at least one package.")
    else:
        # Parse input into list of dependencies
        dependencies = []
        lines = packages_input.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if '==' not in line:
                st.error(f"Invalid format: '{line}'. Please use 'package==version'")
                st.stop()
            name, version = line.split('==', 1)
            dependencies.append({"name": name.strip(), "version": version.strip()})

        # Prepare request payload
        payload = {"dependencies": dependencies}

        # Show loading spinner while making request
        with st.spinner("Scanning dependencies against threat intelligence feeds..."):
            try:
                # Make POST request to FastAPI backend
                response = requests.post(
                    "https://cybersentinel-w01q.onrender.com/api/v1/audit",
                    json=payload,
                    timeout=30
                )

                # Check if request was successful
                if response.status_code == 200:
                    data = response.json()

                    overall_score = data.get("overall_score", 0)
                    dependencies_data = data.get("dependencies", [])

                    packages_scanned = len(dependencies_data)
                    critical_count = sum(1 for dep in dependencies_data if dep.get("score", 100) < 40)

                    # ------------------------------------------------------------
                    # KPI Dashboard - Top Row
                    # ------------------------------------------------------------
                    st.subheader("📊 Threat Overview")
                    kpi1, kpi2, kpi3 = st.columns(3)

                    score_wrapper_class = "safe-metric" if overall_score >= 80 else (
                        "critical-metric" if overall_score < 40 else ""
                    )
                    score_delta = "Secure" if overall_score >= 80 else (
                        "Critical Risk" if overall_score < 40 else "Moderate Risk"
                    )
                    score_delta_color = "normal" if overall_score >= 80 else "inverse"

                    with kpi1:
                        st.markdown(f"<div class='{score_wrapper_class}'>", unsafe_allow_html=True)
                        st.metric(
                            label="Overall Security Score",
                            value=f"{overall_score}/100",
                            delta=score_delta,
                            delta_color=score_delta_color
                        )
                        st.markdown("</div>", unsafe_allow_html=True)

                    with kpi2:
                        st.metric(
                            label="Packages Scanned",
                            value=packages_scanned
                        )

                    with kpi3:
                        crit_wrapper_class = "critical-metric" if critical_count > 0 else "safe-metric"
                        st.markdown(f"<div class='{crit_wrapper_class}'>", unsafe_allow_html=True)
                        st.metric(
                            label="Critical Vulnerabilities Found",
                            value=critical_count,
                            delta="Action Required" if critical_count > 0 else "Clear",
                            delta_color="inverse" if critical_count > 0 else "normal"
                        )
                        st.markdown("</div>", unsafe_allow_html=True)

                    st.markdown("---")

                    # ------------------------------------------------------------
                    # Visualization - Main Body
                    # ------------------------------------------------------------
                    if dependencies_data:
                        df = pd.DataFrame([
                            {
                                "Package": f"{dep['name']}@{dep['version']}",
                                "Score": dep["score"],
                                "Flags": ", ".join(dep["flags"]) if dep["flags"] else "None"
                            }
                            for dep in dependencies_data
                        ])

                        def get_color(score):
                            if score > 80:
                                return "Neon Green"
                            elif score >= 40:
                                return "Yellow"
                            else:
                                return "Neon Red"

                        df["Risk Level"] = df["Score"].apply(get_color)

                        st.subheader("📈 Individual Package Risk Scores")

                        fig = px.bar(
                            df,
                            y="Package",
                            x="Score",
                            orientation='h',
                            title="Individual Package Risk Scores",
                            color="Risk Level",
                            color_discrete_map={
                                "Neon Green": "#39FF14",
                                "Yellow": "#FFD700",
                                "Neon Red": "#FF073A"
                            },
                            text="Score",
                            template="plotly_dark"
                        )

                        fig.update_layout(
                            xaxis_title="Risk Score (0-100)",
                            yaxis_title="",
                            showlegend=True,
                            height=max(300, len(dependencies_data) * 40),
                            xaxis=dict(range=[0, 100]),
                            plot_bgcolor="#0E1117",
                            paper_bgcolor="#0E1117",
                            font=dict(family="Consolas, Courier New, monospace", color="#E6E6E6")
                        )

                        fig.update_traces(textposition='outside')
                        st.plotly_chart(fig, use_container_width=True)

                        # --------------------------------------------------------
                        # Threat Intel Feed - Bottom
                        # --------------------------------------------------------
                        with st.expander("🚨 Detailed Threat Intel Feed", expanded=False):
                            st.subheader("Package Flags and Vulnerability Details")

                            for dep in dependencies_data:
                                package_name = f"{dep['name']}@{dep['version']}"
                                score = dep["score"]
                                flags = dep["flags"]

                                if score >= 80:
                                    risk_color = "#39FF14"
                                elif score >= 40:
                                    risk_color = "#FFD700"
                                else:
                                    risk_color = "#FF073A"

                                st.markdown(f"""
                                <div style="border-left: 4px solid {risk_color}; background-color: #12151C;
                                            padding: 10px 15px; margin-bottom: 15px; border-radius: 4px;">
                                    <h4 style="color: {risk_color}; margin: 0;">{package_name}</h4>
                                    <p style="color: #E6E6E6;"><strong>Score:</strong> {score}/100</p>
                                    <p style="color: #E6E6E6;"><strong>CVE / Flags:</strong></p>
                                </div>
                                """, unsafe_allow_html=True)

                                if flags:
                                    for flag in flags:
                                        st.markdown(
                                            f"<p style='color:#FF073A; font-family: Consolas, monospace; "
                                            f"margin-left: 15px;'>⚠️ {flag}</p>",
                                            unsafe_allow_html=True
                                        )
                                else:
                                    st.markdown(
                                        "<p style='color:#39FF14; font-family: Consolas, monospace; "
                                        "margin-left: 15px;'>✅ No known vulnerabilities</p>",
                                        unsafe_allow_html=True
                                    )

                    else:
                        st.info("No dependency data returned from the scan.")

                else:
                    st.error(f"Backend error: {response.status_code} - {response.text}")

            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to the backend. Please ensure your FastAPI server is running.")
            except requests.exceptions.Timeout:
                st.error("❌ Request timed out. The backend might be busy or unavailable.")
            except Exception as e:
                st.error(f"❌ An unexpected error occurred: {str(e)}")

# ----------------------------------------------------------------------------
# Footer
# ----------------------------------------------------------------------------
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #4A4F5A; font-family: Consolas, monospace; font-size: 0.85em;'>"
    "CyberSentinel SOC Dashboard &bull; Powered by Streamlit &amp; Plotly &bull; Threat Intel Engine v1.0"
    "</div>",
    unsafe_allow_html=True
)
