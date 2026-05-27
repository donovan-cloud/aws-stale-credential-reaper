### 2. `credential_reaper.py`
```python
#!/usr/bin/env python3
"""
AWS Stale IAM Credential Reaper
Finds and programmatically disables user access keys that are older than 90 days.
"""

import boto3
import json
from datetime import datetime, timezone

# Compliance Threshold
AGE_MAX_THRESHOLD_DAYS = 90

def main():
    print("[+] Initiating AWS Identity Governance Credential Reaper...")
    iam_client = boto3.client('iam')
    remediated_keys_log = []
    now = datetime.now(timezone.utc)

    try:
        users = iam_client.list_users(MaxItems=100)['Users']
    except Exception as e:
        print(f"[-] Execution stopped. IAM permissions missing: {str(e)}")
        return

    for user in users:
        username = user['UserName']
        
        # Pull key records associated with the target identity
        access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in access_keys:
            key_id = key['AccessKeyId']
            status = key['Status']
            create_date = key['CreateDate'].replace(tzinfo=timezone.utc)
            
            # Compute age delta metrics
            key_age_days = (now - create_date).days
            
            if key_age_days >= AGE_MAX_THRESHOLD_DAYS and status == 'Active':
                print(f"[!] User [{username}] possesses stale Active key: {key_id} ({key_age_days} days old)")
                
                # EXECUTE MITIGATION STRATEGY: Flip state safely to Inactive
                try:
                    iam_client.update_access_key(
                        UserName=username,
                        AccessKeyId=key_id,
                        Status='Inactive'
                    )
                    remediated_keys_log.append({
                        "UserName": username,
                        "AccessKeyId": key_id,
                        "KeyAgeDays": key_age_days,
                        "ActionExecuted": "CHANGED_STATUS_TO_INACTIVE"
                    })
                except Exception as ex:
                    print(f"[-] Failed to mutate key status for {key_id}: {str(ex)}")

    # Archive execution telemetry to local ledger target
    archive_payload = {
        "ReaperExecutionTimestamp": now.isoformat(),
        "ComplianceAgeLimitConfigured": AGE_MAX_THRESHOLD_DAYS,
        "TotalKeysRemediated": len(remediated_keys_log),
        "RemediationActionsLedger": remediated_keys_log
    }

    with open('reaper_remediation_log.json', 'w') as f:
        json.dump(archive_payload, f, indent=4)
    print(f"[+] Identity harvest complete. Remediated ({len(remediated_keys_log)}) stale keys.")

if __name__ == '__main__':
    main()
