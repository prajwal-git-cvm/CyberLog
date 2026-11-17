
import pandas as pd


FAILED_LOGIN_THRESHOLD = 5
HIGH_ACTIVITY_THRESHOLD = 20
MULTIPLE_USERS_THRESHOLD = 4


def detect_brute_force(logs):

    failed_logins = logs[
        (logs["event_type"].str.lower() == "login") &
        (logs["status"].str.lower() == "failed")
    ]

    suspicious_ips = failed_logins["source_ip"].value_counts()

    suspicious_ips = suspicious_ips[
        suspicious_ips >= FAILED_LOGIN_THRESHOLD
    ]

    threats = []

    for ip, count in suspicious_ips.items():
        threats.append({
            "source_ip": ip,
            "threat_type": "Brute Force Attack",
            "attempts": count,
            "severity": "High"
        })

    return threats


def detect_high_activity(logs):

    ip_activity = logs["source_ip"].value_counts()

    suspicious_ips = ip_activity[
        ip_activity >= HIGH_ACTIVITY_THRESHOLD
    ]

    threats = []

    for ip, count in suspicious_ips.items():
        threats.append({
            "source_ip": ip,
            "threat_type": "Unusual High Activity",
            "attempts": count,
            "severity": "Medium"
        })

    return threats


def detect_multiple_users(logs):

    user_counts = logs.groupby("source_ip")["username"].nunique()

    suspicious_ips = user_counts[
        user_counts >= MULTIPLE_USERS_THRESHOLD
    ]

    threats = []

    for ip, count in suspicious_ips.items():
        threats.append({
            "source_ip": ip,
            "threat_type": "Multiple Account Access",
            "attempts": count,
            "severity": "Medium"
        })

    return threats


def detect_threats(logs):

    if logs.empty:
        return pd.DataFrame(
            columns=[
                "source_ip",
                "threat_type",
                "attempts",
                "severity"
            ]
        )

    threats = []

    threats.extend(detect_brute_force(logs))
    threats.extend(detect_high_activity(logs))
    threats.extend(detect_multiple_users(logs))

    return pd.DataFrame(threats)

