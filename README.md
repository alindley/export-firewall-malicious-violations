# export-firewall-malicious-violations
This script will produce a csv for a given Nexus Repository Manager instance with all the Security-Malicious violations for all repositories where Firewall audit has been configured.

## Requirements
Python3

## Execution
Modify the variables which relate to your Security Malicious Policy Name, IQ Server URL, Username and Password at the top of the script.

Execute the script with the 'list' parameter to get a list of all the Nexus Repository Managers connected to your IQ Server. 
This script can only be run for each individual Nexus Repository Manager.
```
python export-firewall-malicious-violations.py list
```
Once you have a Nexus Repository ID from the list provided use it with the export parameter to create a csv list of all the Security-Malicious violations.
```
python export-firewall-malicious-violations.py export <reposistory_manager_id>
```
## Disclaimer 
This script should be tested thoroughly before use on any production IQ Server instance. This script is not supported by Sonatype and is provided as-is with MIT licence.
