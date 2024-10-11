import requests
import json
import csv
import sys
import os
from datetime import datetime

# Default values for IQ Server URL and credentials
IQ_SERVER_URL = "http://localhost:8070"
USERNAME = "admin"
PASSWORD = "admin123"
MALICIOUS_POLICY_NAME = "Security-Malicious"

def usage():
    print("Usage: script.py list/export [...]")
    print("  - list: list repository managers added to IQ server to get the Nexus Repository id")
    print("  - export <id>: This must be the Nexus Repository 'id' NOT the 'instanceId'")
    sys.exit(1)

# Check if the required argument is provided
if len(sys.argv) < 2:
    usage()

# Function to export data based on repository ID
def run_export(repo_id):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"firewall_malicious_violations_{timestamp}.csv"

    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ["repositoryName", "repositoryId", "componentDisplayText", "pathname"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        repo_names_response = requests.get(f"{IQ_SERVER_URL}/api/v2/firewall/repositories/configuration/{repo_id}",
                                           auth=(USERNAME, PASSWORD)).json()

        repo_map = {}
        for repo in repo_names_response.get('repositories', []):
            repository_id = repo.get('repositoryId')
            public_id = repo.get('publicId')
            repo_map[repository_id] = public_id

        repo_results_response = requests.post(f"{IQ_SERVER_URL}/api/experimental/repositories/repository_manager/{repo_id}/results/details",
                                              headers={'Content-Type': 'application/json'},
                                              auth=(USERNAME, PASSWORD),
                                              json={
                                                  "page": 1,
                                                  "pageSize": 10000,
                                                  "searchFilters": [
                                                      {"filterableField": "POLICY_NAME",
                                                       "value": MALICIOUS_POLICY_NAME}
                                                  ],
                                                  "matchStateFilters": ["MATCH_STATE_ALL"],
                                                  "violationStateFilters": ["VIOLATION_STATE_ALL"],
                                                  "sortFields": [
                                                      {"sortableField": "COMPONENT_COORDINATES",
                                                       "asc": False,
                                                       "sortPriority": 1}
                                                  ],
                                                  "aggregate": False
                                              }).json()

        # Write results to CSV
        for result in repo_results_response.get('repositoryResultsDetails', []):
            repository_id = result.get('repositoryId')
            public_id = repo_map.get(repository_id, "Unknown")
            component_display_text = result.get('componentDisplayText', "Unknown")
            pathname = result.get('pathname', "Unknown")
            writer.writerow({
                "repositoryName": public_id,
                "repositoryId": repository_id,
                "componentDisplayText": component_display_text,
                "pathname": pathname
            })

    print(f"Export complete, saved to {output_file}")

# Function to list repository managers
def list_repository_managers():
    response = requests.get(f"{IQ_SERVER_URL}/api/v2/firewall/repositoryManagers", auth=tuple(CREDENTIALS.split(":")))
    print(json.dumps(response.json(), indent=2))

# Main function to handle command-line arguments
if __name__ == "__main__":
    command = sys.argv[1]

    if command == "list":
        list_repository_managers()
    elif command == "export":
        if len(sys.argv) < 3:
            print("Error: export command requires a repository id.")
            usage()
        else:
            repo_id = sys.argv[2]
            run_export(repo_id)
    else:
        print(f"Invalid command: '{command}'")
        usage()
