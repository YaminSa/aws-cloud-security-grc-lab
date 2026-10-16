# Plan of Action and Milestones (POA&M)

**System:** Cloud Security Lab, single AWS account (us-east-1)
**Owner:** Yamin Salahi
**Created:** Oct 15, 2026, after the post-remediation Prowler scan

A POA&M tracks weaknesses that are known but not fixed yet. Each item has a source, the control it affects, a planned fix, and a date to hold myself to.

## Open items

| ID | Weakness | Source | Control | Severity | Planned action | Milestone | Status |
|---|---|---|---|---|---|---|---|
| POA&M-01 | Prowler still reports the deleted access key as unused and unrotated | Prowler `iam_user_accesskey_unused`, `iam_rotate_access_key_90_days` | AC-2(3) | Medium | No fix needed. `list-access-keys` returns an empty list. Prowler reads the IAM credential report, which AWS refreshes every 4 hours. Rerun these two checks to close with scanner evidence. | Oct 16, 2026 | Open, pending evidence refresh |
| POA&M-02 | Legacy service roles `DemoRoleForEC2` and `s3crr_role_for_s3-yamin-bucket-origin-v2` lack confused deputy conditions | Prowler `iam_role_cross_service_confused_deputy_prevention` (High) | AC-6 | High | Check last-used date in IAM. If unused, delete. If kept, add an `aws:SourceAccount` condition to the trust policy. | Oct 22, 2026 | Open |
| POA&M-03 | Leftover training buckets (`s3-storage-classes-demo-yamin`, `s3-yamin-bucket-origin-v2`, `s3-yamin-bucket-replica-v2`, `yamin-demo-s3-v1`) with no HTTPS-only policy and no owner of record | Prowler `s3_bucket_secure_transport_policy`, cost review | CM-8, SC-8 | Medium | Decommission buckets that are no longer needed. Apply the same `DenyInsecureTransport` statement to any that stay. | Oct 22, 2026 | Open |
| POA&M-04 | No alarms for S3 bucket policy changes (CIS 4.8) or network changes (CIS 4.11 to 4.14) | Prowler CIS 4.0 report | SI-4, CM-3 | Medium | Add 2 metric filters to the CloudFormation template: one for S3 policy changes, one combined filter for VPC, route table, NACL and gateway changes. Keeps the total at 8 alarms, under the free tier limit of 10. | Oct 25, 2026 | Open |

## Closed or will not fix

| ID | Weakness | Decision | Reason |
|---|---|---|---|
| POA&M-05 | CloudFormation stack had no termination protection | Closed Oct 15, 2026 | Enabled with `update-termination-protection` |
| POA&M-06 | GuardDuty free trial ending | Closed Oct 15, 2026 | Detector deleted at teardown, `list-detectors` returns `[]`. Tracked as accepted risk R-14. |
| POA&M-07 | MFA Delete not enabled on the CloudTrail log bucket (CIS 2.1.2) | Will not fix | MFA Delete can only be turned on with root access keys through the CLI. Creating root access keys would break CIS 1.4 and add more risk than it removes. Versioning and log file validation already protect the logs. |
| POA&M-08 | Password expiration not set | Will not fix | Documented deviation, see R-08 (NIST SP 800-63B) |

## Remediation completed on Oct 15, 2026

For reference, these were found in the baseline scan and fixed the same day. They are tracked in the risk register as closed.

| Finding | Severity | Fix | Verified by |
|---|---|---|---|
| Public S3 bucket `yamin-demo-s3-v1` | Critical | Account-level Block Public Access, bucket policy deleted | `curl` returns 403, Prowler rescan PASS |
| Account and bucket Block Public Access off | High | Account-level Block Public Access | Prowler rescan PASS |
| Stale access key (130 days) | Medium | Deactivated and deleted | `list-access-keys` returns `[]` |
| No IAM password policy | Medium | 14 char policy with complexity and history | Prowler rescan PASS (6 checks) |
| IAM Access Analyzer off | Low | Analyzer created | Prowler rescan PASS |
| Log bucket allows HTTP | Medium | `DenyInsecureTransport` statement added | Prowler rescan PASS, trail delivery confirmed |
| Log bucket versioning off | Medium | Versioning enabled | Prowler rescan PASS |
