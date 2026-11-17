
import pandas as pd
import numpy as np


def analyze_logs(logs):

    if logs.empty:
        raise ValueError("No log data available for analysis.")

    analysis = {}

    analysis["total_events"] = len(logs)

    analysis["unique_ips"] = logs["source_ip"].nunique()

    analysis["unique_users"] = logs["username"].nunique()

    analysis["failed_events"] = (
        logs["status"].str.lower() == "failed"
    ).sum()

    analysis["successful_events"] = (
        logs["status"].str.lower() == "success"
    ).sum()

    analysis["event_types"] = logs["event_type"].value_counts()

    analysis["status_counts"] = logs["status"].value_counts()

    analysis["top_ips"] = logs["source_ip"].value_counts().head(5)

    analysis["top_users"] = logs["username"].value_counts().head(5)

    analysis["failure_percentage"] = np.round(
        (analysis["failed_events"] / analysis["total_events"]) * 100,
        2
    )

    return analysis


def analyze_timestamps(logs):

    timestamps = pd.to_datetime(
        logs["timestamp"],
        errors="coerce"
    )

    valid_timestamps = timestamps.dropna()

    if valid_timestamps.empty:
        return pd.Series(dtype="int64")

    hourly_activity = valid_timestamps.dt.hour.value_counts()

    return hourly_activity.sort_index()


def get_event_summary(logs):

    return logs.groupby("event_type").size().sort_values(
        ascending=False
    )


def get_ip_activity(logs):

    return logs.groupby("source_ip").size().sort_values(
        ascending=False
    )


def get_failed_logins(logs):

    failed_logs = logs[
        (logs["event_type"].str.lower() == "login") &
        (logs["status"].str.lower() == "failed")
    ]

    return failed_logs

