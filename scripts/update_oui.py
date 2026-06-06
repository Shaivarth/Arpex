import csv
import json
import requests
from pathlib import Path


IEEE_OUI_URL = (
    "https://standards-oui.ieee.org/oui/oui.csv"
)


def download_oui_database():

    print(
        "[ARPEX] Downloading IEEE OUI database..."
    )

    response = requests.get(
        IEEE_OUI_URL,
        timeout=60
    )

    response.raise_for_status()

    return response.text


def parse_oui_csv(
    csv_text: str
) -> dict:

    oui_map = {}

    reader = csv.DictReader(
        csv_text.splitlines()
    )

    for row in reader:

        assignment = row.get(
            "Assignment"
        )

        organization = row.get(
            "Organization Name"
        )

        if not assignment:
            continue

        oui_map[
            assignment.upper()
        ] = organization

    return oui_map


def save_database(
    oui_map: dict
):

    Path(
        "config"
    ).mkdir(
        exist_ok=True
    )

    output_file = (
        Path("config")
        /
        "oui.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            oui_map,
            f,
            indent=4
        )

    print(
        f"[ARPEX] Saved "
        f"{len(oui_map)} "
        f"OUI entries."
    )


def main():

    csv_text = (
        download_oui_database()
    )

    oui_map = (
        parse_oui_csv(
            csv_text
        )
    )

    save_database(
        oui_map
    )


if __name__ == "__main__":

    main()