import json
import csv
import logging
import requests
import pandas as pd

API_KEY = "52062897c4f9378b2a0c351ee3d0f3032fb89fe960ab39eb"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_LOCAL = "./threatfox_ioc_180225.csv"

def get_threatfox_iocs():
    # query recent IOCs (last 7 days)
    payload = {"query": "get_iocs", "days": 7}
    headers = {"Auth-Key": API_KEY}

    try:
        response = requests.post(THREATFOX, headers=headers, json=payload)
    except Exception as e:
        logging.error("Error: %s", e)
        return

    if response.status_code == 200:
        data = response.json()

        with open(THREATFOX_LOCAL, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                "ioc",
                "threat_type",
                "threat_type_desc",
                "ioc_type",
                "ioc_type_desc",
                "malware",
                "malware_printable",
                "malware_alias",
                "malware_malpedia",
                "confidence_level",
                "first_seen",
                "last_seen",
                "reference",
                "reporter"
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in data.get("data", []):
                entry.pop('tags', None)
                entry.pop('id', None)
                writer.writerow(entry)
                # print(f"IOC: {entry['ioc']} - {entry['ioc_type']} ({entry['ioc_type_desc']}) |\n\
                #         Threat Type: {entry['threat_type']} ({entry['threat_type_desc']}) |\n\
                #         Malware: {entry.get('malware', 'Unknown')}")
    else:
        print(f"Error: {response.status_code}")


def main():
    get_threatfox_iocs()
    # get_urlhaus_recent()
    # get_malwarebazaar_recent()
    # get_latest_cves()


if __name__ == "__main__":
    main()


# def get_urlhaus_recent():
#     url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
#     response = requests.get(url)
#     if response.status_code == 200:
#         data = response.json()
#         for entry in data.get("urls", [])[:5]:  # Limit output to 5 results
#             print(f"URL: {entry['url']} | Status: {entry['status']} | Threat: {entry.get('threat', 'Unknown')}")
#     else:
#         print(f"Error: {response.status_code}")

# def get_malwarebazaar_recent():
#     url = "https://mb-api.abuse.ch/api/v1/"
#     payload = {"query": "get_recent"}
#     response = requests.post(url, json=payload)
#     if response.status_code == 200:
#         data = response.json()
#         for entry in data.get("data", [])[:5]:  # Limit to 5 results
#             print(f"SHA256: {entry['sha256_hash']} | Malware: {entry.get('signature', 'Unknown')}")
#     else:
#         print(f"Error: {response.status_code}")

# def get_latest_cves():
#     url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
#     params = {"resultsPerPage": 5}  # Get 5 latest CVEs
#     response = requests.get(url, params=params)
#     if response.status_code == 200:
#         data = response.json()
#         for cve in data.get("result", {}).get("CVE_Items", []):
#             cve_id = cve["cve"]["CVE_data_meta"]["ID"]
#             description = cve["cve"]["description"]["description_data"][0]["value"]
#             print(f"{cve_id}: {description}")
#     else:
#         print(f"Error: {response.status_code}")
