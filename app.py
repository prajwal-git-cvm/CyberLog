
import streamlit as st
import matplotlib.pyplot as plt
from pathlib import Path

from log_reader import load_logs
from log_analyzer import analyze_logs
from threat_detector import detect_threats
from ip_locator import locate_ips

from visualization import (
    event_type_chart,
    login_status_chart,
    top_ip_chart,
    hourly_activity_chart,
    threat_severity_chart
)

from report_generator import (
    generate_logs_csv,
    generate_threats_csv,
    generate_json_report
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="CyberLog | Security Dashboard",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)


# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

st.markdown("""
<style>

.stApp {
    background-color: #0B1120;
    color: #E2E8F0;
}

[data-testid="stSidebar"] {
    background-color: #111B2E;
    border-right: 1px solid #263449;
}

[data-testid="stHeader"] {
    background-color: #0B1120;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}

h1, h2, h3 {
    color: #F1F5F9 !important;
}

p, label {
    color: #CBD5E1;
}

.metric-card {
    background: #142137;
    border: 1px solid #263A55;
    border-radius: 12px;
    padding: 18px;
    min-height: 110px;
}

.metric-label {
    color: #94A3B8;
    font-size: 13px;
    margin-bottom: 8px;
}

.metric-value {
    color: #F8FAFC;
    font-size: 27px;
    font-weight: 700;
}

.section-card {
    background: #111C30;
    border: 1px solid #263449;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 15px;
}

.threat-high {
    color: #F87171;
    font-weight: bold;
}

.threat-medium {
    color: #FBBF24;
    font-weight: bold;
}

div[data-testid="stMetric"] {
    background: #142137;
    border: 1px solid #263A55;
    padding: 15px;
    border-radius: 12px;
}

div[data-testid="stMetricLabel"] {
    color: #94A3B8;
}

div[data-testid="stMetricValue"] {
    color: #F8FAFC;
}

.stButton button,
.stDownloadButton button {
    background-color: #2563EB;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 8px 16px;
}

.stButton button:hover,
.stDownloadButton button:hover {
    background-color: #1D4ED8;
    color: white;
    border: none;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #263449;
    border-radius: 10px;
}

hr {
    border-color: #263449;
}

</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:

    st.title("CyberLog")

    st.caption("SECURITY MONITORING SYSTEM")

    st.divider()

    st.subheader("Log Management")

    uploaded_file = st.file_uploader(
        "Upload security logs",
        type=["csv"]
    )

    st.caption(
        "Upload a CSV file containing security event records."
    )

    st.divider()

    st.subheader("System Information")

    st.write("Analysis: Rule-based")
    st.write("Storage: CSV / JSON")
    st.write("Visualization: Matplotlib")
    st.write("Interface: Streamlit")

    st.divider()

    st.caption("CyberLog | Version 1.0")


# --------------------------------------------------
# FILE PATHS
# --------------------------------------------------

base_path = Path(__file__).parent

sample_file = (
    base_path / "data" / "security_event_logs.csv"
)

geo_database = (
    base_path / "data" / "ip_geolocation.csv"
)


# --------------------------------------------------
# LOAD LOG FILE
# --------------------------------------------------

if uploaded_file is not None:
    log_file = uploaded_file

elif sample_file.exists():
    log_file = sample_file

else:
    st.warning(
        "Upload a security log CSV file to start analysis."
    )
    st.stop()


try:
    logs = load_logs(log_file)

except Exception as error:
    st.error(f"Unable to read logs: {error}")
    st.stop()


# --------------------------------------------------
# ANALYSIS AND THREAT DETECTION
# --------------------------------------------------

try:
    analysis = analyze_logs(logs)
    threats = detect_threats(logs)

except Exception as error:
    st.error(f"Analysis failed: {error}")
    st.stop()


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.markdown(
    "<h1>Security Operations Dashboard</h1>",
    unsafe_allow_html=True
)

st.caption(
    "Monitor security events, analyze suspicious activities "
    "and investigate potentially malicious IP addresses."
)

st.divider()


# --------------------------------------------------
# SECURITY OVERVIEW
# --------------------------------------------------

st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total Events",
        analysis["total_events"]
    )

with col2:
    st.metric(
        "Unique IP Addresses",
        analysis["unique_ips"]
    )

with col3:
    st.metric(
        "Failed Events",
        analysis["failed_events"]
    )

with col4:
    st.metric(
        "Detected Threats",
        len(threats)
    )


col5, col6, col7 = st.columns(3)

with col5:
    st.metric(
        "Successful Events",
        analysis["successful_events"]
    )

with col6:
    st.metric(
        "Unique Users",
        analysis["unique_users"]
    )

with col7:
    st.metric(
        "Failure Percentage",
        f'{analysis["failure_percentage"]}%'
    )


st.divider()


# --------------------------------------------------
# SECURITY ANALYTICS
# --------------------------------------------------

st.subheader("Security Analytics")

col1, col2 = st.columns(2)

with col1:
    with st.container(border=True):
        st.markdown("**Event Type Distribution**")

        fig = event_type_chart(logs)
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)


with col2:
    with st.container(border=True):
        st.markdown("**Login Status Distribution**")

        fig = login_status_chart(logs)
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)


col3, col4 = st.columns(2)

with col3:
    with st.container(border=True):
        st.markdown("**Top Active IP Addresses**")

        fig = top_ip_chart(logs)
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)


with col4:
    with st.container(border=True):
        st.markdown("**Hourly Security Activity**")

        fig = hourly_activity_chart(logs)
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)


st.divider()


# --------------------------------------------------
# THREAT DETECTION
# --------------------------------------------------

st.subheader("Threat Detection")

if threats.empty:

    st.success("No suspicious activities detected.")

else:
    st.warning(
        f"{len(threats)} suspicious activities detected. "
        "Further investigation is recommended."
    )
    st.dataframe(threats, use_container_width=True)


# --------------------------------------------------
# THREAT SEVERITY
# --------------------------------------------------

st.subheader("Threat Severity Analysis")

fig = threat_severity_chart(threats)

st.pyplot(
    fig,
    use_container_width=True
)

plt.close(fig)


st.divider()


# --------------------------------------------------
# IP LOCATION MAP
# --------------------------------------------------

st.subheader("IP Geolocation Analysis")

st.caption(
    "Approximate geographical locations of suspicious public IP addresses."
)

if threats.empty:

    st.info("No suspicious IP addresses available for mapping.")

elif not geo_database.exists():

    st.warning(
        "IP geolocation database is missing. "
        "Add ip_geolocation.csv inside the data folder."
    )

else:

    try:

        suspicious_ips = threats["source_ip"].dropna().unique()

        suspicious_logs = logs[
            logs["source_ip"].isin(suspicious_ips)
        ]

        locations = locate_ips(
            suspicious_logs,
            geo_database
        )

        if locations.empty:

            st.info(
                "No matching geographical locations found."
            )

        else:

            st.markdown(
                '<div class="section-card">'
                '<strong>Suspicious IP Locations</strong>'
                '</div>',
                unsafe_allow_html=True
            )

            map_col1, map_col2 = st.columns([2, 1])

            with map_col1:

                st.map(
                    locations[["lat", "lon"]],
                    use_container_width=True,
                    zoom=1
                )

            with map_col2:

                st.metric(
                    "Mapped IP Addresses",
                    locations["source_ip"].nunique()
                )

                st.metric(
                    "Countries Identified",
                    locations["country"].nunique()
                )

                st.metric(
                    "Cities Identified",
                    locations["city"].nunique()
                )

            st.markdown("**IP Location Details**")

            st.dataframe(
                locations[
                    [
                        "source_ip",
                        "country",
                        "region",
                        "city",
                        "latitude",
                        "longitude"
                    ]
                ],
                use_container_width=True,
                hide_index=True
            )

    except Exception as error:

        st.error(
            f"Unable to display IP locations: {error}"
        )


st.divider()


# --------------------------------------------------
# SECURITY EVENT LOGS
# --------------------------------------------------

st.subheader("Security Event Logs")

st.caption(
    f"Displaying {len(logs)} security event records."
)

st.dataframe(
    logs,
    use_container_width=True,
    hide_index=True
)


st.divider()


# --------------------------------------------------
# REPORT DOWNLOADS
# --------------------------------------------------

st.subheader("Download Security Reports")

st.caption(
    "Export security logs, detected threats and analysis results."
)

col1, col2, col3 = st.columns(3)

with col1:

    st.download_button(
        "Download Logs CSV",
        data=generate_logs_csv(logs),
        file_name="security_logs.csv",
        mime="text/csv",
        use_container_width=True
    )

with col2:

    st.download_button(
        "Download Threat CSV",
        data=generate_threats_csv(threats)
        if not threats.empty else "",
        file_name="threat_report.csv",
        mime="text/csv",
        disabled=threats.empty,
        use_container_width=True
    )

with col3:

    st.download_button(
        "Download JSON Report",
        data=generate_json_report(logs, threats),
        file_name="cyberlog_report.json",
        mime="application/json",
        use_container_width=True
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.markdown(
    """
    <div style="text-align:center; color:#64748B; padding:15px;">
        CyberLog | Security Log Analysis and Threat Detection
        <br>
        Offline Security Analysis Platform
    </div>
    """,
    unsafe_allow_html=True
)
