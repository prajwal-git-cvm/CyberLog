
import pandas as pd
import ipaddress


REQUIRED_COLUMNS = [
    "network",
    "country",
    "region",
    "city",
    "latitude",
    "longitude"
]


def locate_ips(logs, database_path):

    database = pd.read_csv(database_path)

    database.columns = [
        column.strip().lower()
        for column in database.columns
    ]

    missing = [
        column for column in REQUIRED_COLUMNS
        if column not in database.columns
    ]

    if missing:
        raise ValueError(
            "Missing database columns: " + ", ".join(missing)
        )

    ip_database = []

    for _, row in database.iterrows():
        try:
            network = ipaddress.ip_network(
                str(row["network"]).strip(),
                strict=False
            )

            ip_database.append({
                "network": network,
                "country": row["country"],
                "region": row["region"],
                "city": row["city"],
                "latitude": float(row["latitude"]),
                "longitude": float(row["longitude"])
            })

        except (ValueError, TypeError):
            continue

    locations = []

    for ip in logs["source_ip"].dropna().unique():

        try:
            address = ipaddress.ip_address(str(ip).strip())

            if not address.is_global:
                continue

            for record in ip_database:

                network = record["network"]

                if (
                    address.version == network.version
                    and address in network
                ):
                    locations.append({
                        "source_ip": str(ip),
                        "country": record["country"],
                        "region": record["region"],
                        "city": record["city"],
                        "latitude": record["latitude"],
                        "longitude": record["longitude"],
                        "lat": record["latitude"],
                        "lon": record["longitude"]
                    })

                    break

        except ValueError:
            continue

    return pd.DataFrame(locations)
