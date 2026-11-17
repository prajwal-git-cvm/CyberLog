
import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp",
    "source_ip",
    "event_type",
    "username",
    "status"
]


def load_logs(file_path):
    try:
        logs = pd.read_csv(file_path)

        if logs.empty:
            raise ValueError("The log file is empty.")

        logs.columns = [
            str(column).strip().lower()
            for column in logs.columns
        ]

        logs = logs.dropna(how="all")

        for column in logs.select_dtypes(include="object").columns:
            logs[column] = logs[column].str.strip()

        validate_logs(logs)

        return logs

    except Exception as error:
        raise ValueError(f"Error reading log file: {error}")


def validate_logs(logs):
    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in logs.columns
    ]

    if missing_columns:
        raise ValueError(
            "Missing required columns: "
            + ", ".join(missing_columns)
        )

    return True

