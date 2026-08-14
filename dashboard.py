import streamlit as st
import requests
import plotly.express as px
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="SupplyChain Sentinel: NPM Risk Dashboard",
    page_icon="���🛡��️",
    layout="wide"
)

# Title
st.title("���🛡��️ SupplyChain Sentinel: NPM Risk Dashboard")
st.markdown("---")

# Input section
st.subheader("Enter NPM Dependencies")
st.markdown("Format: one package per line as `package_name==version` (e.g., `lodash==4.17.15`)")

# Text area for package input
packages_input = st.text_area(
    "Packages",
    height=150,
    placeholder="lodash==4.17.15\nexpress==4.18.2\nreact==18.2.0"
)

# Scan button
if st.button("���🔍 Scan Dependencies", type="primary"):
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
        with st.spinner("Scanning dependencies..."):
            try:
                # Make POST request to FastAPI backend
                response = requests.post(
                    "http://localhost:8000/api/v1/audit",
                    json=payload,
                    timeout=30
                )

                # Check if request was successful
                if response.status_code == 200:
                    data = response.json()

                    # Display overall score
                    overall_score = data.get("overall_score", 0)
                    st.metric(
                        label="Overall Security Score",
                        value=f"{overall_score}/100",
                        delta=None
                    )

                    # Process dependencies for visualization
                    dependencies_data = data.get("dependencies", [])

                    if dependencies_data:
                        # Create DataFrame for plotting
                        df = pd.DataFrame([
                            {
                                "Package": f"{dep['name']}@{dep['version']}",
                                "Score": dep["score"],
                                "Flags": ", ".join(dep["flags"]) if dep["flags"] else "None"
                            }
                            for dep in dependencies_data
                        ])

                        # Define color based on score
                        def get_color(score):
                            if score >= 80:
                                return "Green"
                            elif score >= 40:
                                return "Yellow"
                            else:
                                return "Red"

                        df["Risk Level"] = df["Score"].apply(get_color)

                        # Create horizontal bar chart
                        fig = px.bar(
                            df,
                            y="Package",
                            x="Score",
                            orientation='h',
                            title="Individual Package Risk Scores",
                            color="Risk Level",
                            color_discrete_map={
                                "Green": "#2E8B57",  # Sea Green
                                "Yellow": "#FFD700", # Gold
                                "Red": "#DC143C"     # Crimson
                            },
                            text="Score"
                        )

                        fig.update_layout(
                            xaxis_title="Risk Score (0-100)",
                            yaxis_title="",
                            showlegend=True,
                            height=max(300, len(dependencies_data) * 40),
                            xaxis=dict(range=[0, 100])
                        )

                        fig.update_traces(textposition='outside')
                        st.plotly_chart(fig, use_container_width=True)

                        # Threat Intel expander
                        with st.expander("���🔍 Threat Intelligence Details", expanded=False):
                            st.subheader("Package Flags and Vulnerability Details")

                            for dep in dependencies_data:
                                package_name = f"{dep['name']}@{dep['version']}"
                                score = dep["score"]
                                flags = dep["flags"]

                                # Determine risk level for styling
                                if score >= 80:
                                    risk_color = "green"
                                elif score >= 40:
                                    risk_color = "orange"
                                else:
                                    risk_color = "red"

                                st.markdown(f"""
                                <div style="border-left: 4px solid {risk_color}; padding-left: 10px; margin-bottom: 15px;">
                                    <h4 style="color: {risk_color}; margin: 0;">{package_name}</h4>
                                    <p><strong>Score:</strong> {score}/100</p>
                                    <p><strong>Flags:</strong>
                                       <span style="color: {'red' if flags else 'green'};">
                                       {', '.join(flags) if flags else 'None (No known vulnerabilities)'}
                                       </span>
                                    </p>
                                </div>
                                """, unsafe_allow_html=True)

                                # Show additional info if available (like specific CVEs)
                                # Note: Our backend doesn't return CVE details, just flags
                                # but we could extend this if needed

                    else:
                        st.info("No dependency data returned from the scan.")

                else:
                    st.error(f"Backend error: {response.status_code} - {response.text}")

            except requests.exceptions.ConnectionError:
                st.error("��❌ Cannot connect to the backend. Please ensure your FastAPI server is running on http://localhost:8000")
            except requests.exceptions.Timeout:
                st.error("��❌ Request timed out. The backend might be busy or unavailable.")
            except Exception as e:
                st.error(f"��❌ An unexpected error occurred: {str(e)}")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "SupplyChain Sentinel - Built with Streamlit & Plotly"
    "</div>",
    unsafe_allow_html=True
)