
import json


def generate_logs_csv(logs):

    if logs.empty:
        raise ValueError("No logs available to export.")

    return logs.to_csv(index=False)


def generate_threats_csv(threats):

    if threats.empty:
        raise ValueError("No threats available to export.")

    return threats.to_csv(index=False)


def generate_json_report(logs, threats):

    if logs.empty:
        raise ValueError("No logs available to export.")

    failed_events = (
        logs["status"].str.lower() == "failed"
    ).sum()

    successful_events = (
        logs["status"].str.lower() == "success"
    ).sum()

    report = {
        "project": "CyberLog",
        "report_type": "Security Analysis Report",

        "summary": {
            "total_events": int(len(logs)),
            "unique_ips": int(logs["source_ip"].nunique()),
            "unique_users": int(logs["username"].nunique()),
            "failed_events": int(failed_events),
            "successful_events": int(successful_events),
            "total_threats": int(len(threats))
        },

        "detected_threats": threats.fillna("").to_dict(
            orient="records"
        ),

        "security_logs": logs.fillna("").to_dict(
            orient="records"
        )
    }

    return json.dumps(
        report,
        indent=4,
        default=str
    )

