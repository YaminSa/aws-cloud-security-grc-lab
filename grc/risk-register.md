# Risk Register

**System:** Cloud Security Lab, single AWS account (us-east-1)
**Owner:** Yamin Salahi
**Last reviewed:** Oct 15, 2026

## Scoring

Likelihood and impact are each rated 1 (low) to 5 (high). **Risk score = Likelihood x Impact.**

| Score | Rating |
|---|---|
| 1 to 5 | Low |
| 6 to 12 | Medium |
| 15 to 25 | High |

Scores are judged for this lab account. Where a real company would rate something differently, the note says so.

## Register

| ID | Risk | L | I | Inherent | Treatment | Controls applied | Residual | Status |
|---|---|---|---|---|---|---|---|---|
| R-01 | **Public S3 bucket.** `yamin-demo-s3-v1` allowed anyone to download its objects through a `Principal: *` policy for about 120 days. | 5 | 4 | **20 High** | Mitigate | Account-level Block Public Access, bucket policy deleted, Access Analyzer enabled to catch future external sharing | 2 Low | Closed |
| R-02 | **Stale long-term access key.** 130 days unused and never rotated. A leaked `AKIA` key works until someone deletes it. | 3 | 4 | **12 Medium** | Mitigate | Key deactivated and deleted. No long-term keys remain. | 1 Low | Closed |
| R-03 | **Single admin with full privileges.** The only IAM user has `AdministratorAccess` through the `admin` group. | 2 | 5 | **10 Medium** | Accept | MFA enforced, IAM policy change alarm (CIS 4.4), root and tampering alerts | 10 Medium | Accepted. In a company: split into role-based groups and use temporary role access. |
| R-04 | **Audit logs not encrypted with a customer managed KMS key** (CIS 3.5). | 1 | 3 | **3 Low** | Accept | SSE-S3 encryption, private bucket, HTTPS only, log file validation | 3 Low | Accepted. Reason: about $1 per month per key, outside the free scope. |
| R-05 | **Can't prove who read S3 data.** No S3 data events (CIS 3.8, 3.9) and no server access logging. Shown by R-01: no record exists of whether the public files were downloaded. | 3 | 3 | **9 Medium** | Accept | Management events logged in all regions. No sensitive data stored. | 9 Medium | Accepted. In a company with customer data this would be High and mitigated. |
| R-06 | **Root session left open in the background.** Found during the CIS 4.3 alarm investigation: the console polled notifications as root for at least 38 minutes. | 3 | 5 | **15 High** | Mitigate | Root usage alarm (tested), session closed, procedure to sign out of root right after use | 4 Low | Closed |
| R-07 | **Unexpected spend from security tools.** | 3 | 2 | **6 Medium** | Mitigate | Zero-spend budget alert set before any service was enabled. Paid services left off. | 2 Low | Closed |
| R-08 | **Passwords never expire.** Prowler flags missing 90 day expiration. | 2 | 2 | **4 Low** | Accept | 14 character complexity rules, 24 password history, MFA required | 4 Low | Accepted. NIST SP 800-63B advises against forced periodic changes because users fall back to predictable patterns. |
| R-09 | **No continuous compliance service** (AWS Config, Security Hub). Drift between scans would go unnoticed. | 3 | 3 | **9 Medium** | Accept | Point-in-time Prowler scans, real-time alerts on IAM, security group, logging and GuardDuty changes | 6 Medium | Accepted. Reason: cost. |
| R-10 | **SNS alert topic not encrypted with KMS.** | 1 | 2 | **2 Low** | Accept | Topic policy limits publishers to EventBridge and CloudWatch in this account. Alert content holds no secrets. | 2 Low | Accepted. AWS managed key blocks EventBridge from publishing, and a customer managed key costs money. |
| R-11 | **Detection gaps.** No alarms for S3 bucket policy changes (CIS 4.8) or VPC, route table, NACL and gateway changes (CIS 4.11 to 4.14). | 2 | 3 | **6 Medium** | Mitigate (planned) | Security group change alarm in place. No VPC workloads run in this account. | 6 Medium | Open, see POA&M-04 |
| R-12 | **Legacy IAM roles without confused deputy protection.** `DemoRoleForEC2` and the S3 replication role have no `aws:SourceAccount` condition. | 2 | 3 | **6 Medium** | Mitigate | None yet | 6 Medium | Open, see POA&M-02 |
| R-13 | **Untracked leftover resources** from earlier training (4 S3 buckets, 2 IAM roles). Unknown assets can't be protected. | 3 | 3 | **9 Medium** | Mitigate | Found by Prowler and cost review | 9 Medium | Open, see POA&M-03 |
| R-14 | **Threat detection ends with the trial.** GuardDuty is disabled at teardown to keep the lab free. | 2 | 3 | **6 Medium** | Accept | CloudTrail and CIS alarms stay active | 6 Medium | Accepted for a lab. A production account would keep GuardDuty on. |

## Summary

| | Count |
|---|---|
| Risks identified | 14 |
| Closed (mitigated) | 4 |
| Accepted with documented reason | 7 |
| Open, tracked in POA&M | 3 |
| High inherent risks | 2 (both closed) |
