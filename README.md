# TrojanDB - Remote Access Trojan (RAT) Intelligence Repository

<p align="center">
  <img src="https://github.com/TrojanDB/entiredatabase/blob/main/logo/trojandbAdesignenlogo.png" alt="TrojanDB Banner" width="200"/>
</p>

## About TrojanDB
TrojanDB is a comprehensive Cyber Threat Intelligence (CTI) platform dedicated to cataloging, analyzing, and mapping Remote Access Trojans (RATs) across multiple operating systems, including Windows and Android. Our main platform provides security researchers and SOC analysts with detailed threat profiles, builder hashes, MITRE ATT&CK mappings, and network behavioral fingerprints.

You can visit the main database and threat profiles here: [https://trojandb.org]

## Repository Purpose
This repository serves as the official Open Source Intelligence (OSINT) and Indicator of Compromise (IOC) database for TrojanDB. While the website provides the analytical overview, this repository houses the raw technical artifacts required for threat hunting and detection engineering.

Here, you will find detection rules and encrypted malware stubs corresponding to the RATs analyzed on our platform.

## Repository Structure
The repository is organized by malware family/name. Each RAT directory follows a standardized structure to ensure easy integration into your defense systems:

    /Malware-Name/
        ├── yara_rules.yar          # Static detection rules for stubs
        └── stub.zip                # Encrypted archives containing the malware stub/payload

## Malware Handling and Sample Access
**WARNING: This repository contains live malware samples (stubs/payloads).**

To prevent accidental execution, antivirus flagging, and to comply with hosting policies, all executable files (.exe, .apk, .bin) are stored within password-protected ZIP archives.

* **Archive Password:** `trojandb`

Do not execute these files on a host machine. All analysis should be conducted within a secure, isolated sandbox or dedicated reverse engineering environment.

## Submitting New Threats
TrojanDB relies on community research to stay updated. If you have discovered a new RAT, a new builder version, or want to contribute better detection rules, please submit them through our official reporting channel.

* **Submit a sample:** [https://trojandb.org/report]
* Please ensure all live malware submissions are sent in a password-protected archive using the password `trojandb`.

## Legal Disclaimer
This repository and its contents are provided strictly for educational, defensive, and cybersecurity research purposes. TrojanDB and its maintainers do not support, encourage, or condone the use of malware for malicious or illegal activities. 

By downloading any files or using the detection rules provided in this repository, you assume full responsibility for your actions. The maintainers shall not be held liable for any direct or indirect damage caused by the misuse of these materials. Use this data at your own risk.
