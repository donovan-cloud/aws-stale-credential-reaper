# AWS Stale IAM Credential Reaper (Identity Lifecycle Automation)

[![Language](https://img.shields.io/badge/Language-Python%203.9%2B-blue.svg)](https://www.python.org/)
[![SDK](https://img.shields.io/badge/SDK-Boto3-orange.svg)](https://aws.amazon.com/pythonsdk/)
[![Security](https://img.shields.io/badge/Governance-Identity%20Lifecycle-blue.svg)](https://aws.amazon.com/iam/)

## Operational Overview

This repository features a security-governance automation script designed to hunt down and disable stale, inactive, or un-rotated IAM User Access Keys that have exceeded corporate lifecycle boundaries (90+ days).

Stale programmatic credentials are the single largest source of identity compromise vectors within AWS environments. This engine targets access keys that haven't been rotated or utilized within the compliance boundary, systematically shifting their status to `Inactive` to neutralize the leak risk without destroying data structures.

---

### Core Security Controls Managed

* **Age Boundary Enforcement:** Calculates precise elapsed time since access key creation dates to flag compliance tracking deviations.
* **Graceful Inactivation Logic:** Disables target credentials programmatically via `update_access_key(Status='Inactive')` as a safe middle step before permanent deletion pipelines.
* **Comprehensive Logging Output:** Outputs a complete structural summary mapping out the specific keys updated during the automation run.

---

## Repository Structural Mapping

```text
aws-stale-credential-reaper/
├── README.md                      # Architecture scope overview
├── credential_reaper.py           # Identity automation script engine
├── requirements.txt               # Script dependencies
└── reaper_remediation_log.json    # Output audit execution ledger
