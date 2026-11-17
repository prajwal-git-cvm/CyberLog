
import matplotlib.pyplot as plt
import pandas as pd


def event_type_chart(logs):

    event_counts = logs["event_type"].value_counts()

    fig, ax = plt.subplots(figsize=(8, 5))

    event_counts.plot(
        kind="bar",
        ax=ax
    )

    ax.set_title("Security Events by Type")
    ax.set_xlabel("Event Type")
    ax.set_ylabel("Number of Events")

    plt.xticks(rotation=45)
    plt.tight_layout()

    return fig


def login_status_chart(logs):

    status_counts = logs["status"].value_counts()

    fig, ax = plt.subplots(figsize=(6, 5))

    status_counts.plot(
        kind="pie",
        autopct="%1.1f%%",
        ax=ax
    )

    ax.set_title("Login Status Distribution")
    ax.set_ylabel("")

    plt.tight_layout()

    return fig


def top_ip_chart(logs):

    ip_counts = logs["source_ip"].value_counts().head(5)

    fig, ax = plt.subplots(figsize=(8, 5))

    ip_counts.plot(
        kind="bar",
        ax=ax
    )

    ax.set_title("Top 5 Active IP Addresses")
    ax.set_xlabel("IP Address")
    ax.set_ylabel("Number of Events")

    plt.xticks(rotation=45)
    plt.tight_layout()

    return fig


def hourly_activity_chart(logs):

    timestamps = pd.to_datetime(
        logs["timestamp"],
        errors="coerce"
    )

    hourly_counts = timestamps.dropna().dt.hour.value_counts()

    hourly_counts = hourly_counts.reindex(
        range(24),
        fill_value=0
    ).sort_index()

    fig, ax = plt.subplots(figsize=(9, 5))

    hourly_counts.plot(
        kind="line",
        marker="o",
        ax=ax
    )

    ax.set_title("Security Activity by Hour")
    ax.set_xlabel("Hour of Day")
    ax.set_ylabel("Number of Events")

    ax.set_xticks(range(24))
    ax.grid(True)

    plt.tight_layout()

    return fig


def threat_severity_chart(threats):

    fig, ax = plt.subplots(figsize=(6, 5))

    if threats.empty:
        ax.text(
            0.5, 0.5,
            "No threats detected",
            ha="center",
            va="center"
        )

        ax.set_title("Threat Severity Distribution")
        ax.axis("off")

    else:
        severity_counts = threats["severity"].value_counts()

        severity_counts.plot(
            kind="bar",
            ax=ax
        )

        ax.set_title("Threat Severity Distribution")
        ax.set_xlabel("Severity")
        ax.set_ylabel("Number of Threats")

        plt.xticks(rotation=0)

    plt.tight_layout()

    return fig

