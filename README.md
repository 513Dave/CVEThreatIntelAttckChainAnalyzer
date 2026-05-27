This utility is written in Python. It was designed to take several factors into consideration:
- CVE and CWE information
- EPSS Model scoring
- CISA Kev Listing
- Known Associated Threat Actors
- Target Sectors
- Target Countries
- Mitre ATT&CK Matrix Reference
This utility also takes into account CWE & CVE combinations that can be used to daisy chain multiple functions to establish a foodhold, lateral movement and other factors.
This Utility takes a weighted scoring model and prioritizes combined daisy chain attacks and individual priorities on a 1-N basis (One being the most urgent)
There is also a window that combines each CVE as a Threat Dossier and offers suggested remediation efforts. 
