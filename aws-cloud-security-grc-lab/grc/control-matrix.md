# Control Mapping Matrix

**System:** Single AWS account, project region us-east-1 (global services included)
**Frameworks:** NIST SP 800-53 Rev. 5, CIS AWS Foundations Benchmark v4.0
**Assessment tool:** Prowler 5.45.0 (baseline and post-remediation scans, Oct 15, 2026)
**Prepared by:** Yamin Salahi

## Status key

| Status | Meaning |
|---|---|
| Implemented | Control is in place and evidence is attached |
| Partial | Some of the control is in place, the gap is tracked in the risk register or POA&M |
| Compensating | Requirement is met by a different mechanism than the benchmark expects |
| Accepted risk | Not implemented on purpose, with a documented reason (see risk register) |

## Matrix

| NIST 800-53 | Control name | CIS AWS 4.0 | How it is implemented here | Evidence | Status |
|---|---|---|---|---|---|
| AC-2 | Account management | 1.12, 1.15 | IAM user gets permissions only through the `admin` group. Unused access key (130 days old) removed. | [03-iam-user-permissions.png](../screenshots/03-iam-user-permissions.png), [41-access-key-removed.png](../screenshots/41-access-key-removed.png) | Implemented |
| AC-2(3) | Disable accounts | 1.12, 1.14 | Stale long-term key deactivated, then deleted | [41-access-key-removed.png](../screenshots/41-access-key-removed.png) | Implemented |
| AC-2(4) | Automated audit actions | 4.4 | Metric filter and alarm on any IAM policy create, change, attach or detach | CloudFormation stack, [24-cfn-resources.png](../screenshots/24-cfn-resources.png) | Implemented |
| AC-3, SC-7 | Access enforcement, boundary protection | 2.1.4 | S3 Block Public Access turned on at the account level. Public policy removed from the demo bucket. | [39-public-bucket-exposure.png](../screenshots/39-public-bucket-exposure.png), [40-public-access-blocked.png](../screenshots/40-public-access-blocked.png) | Implemented (remediated) |
| AC-6 | Least privilege | 1.16, 1.20 | Service roles scoped to one resource (CloudTrail to CloudWatch role, log bucket policy with `aws:SourceArn`). IAM Access Analyzer enabled. Single admin still has `AdministratorAccess`. | [09-log-bucket-permissions.png](../screenshots/09-log-bucket-permissions.png), [17-cwlogs-role-policy.png](../screenshots/17-cwlogs-role-policy.png), [42-password-policy-access-analyzer.png](../screenshots/42-password-policy-access-analyzer.png) | Partial (R-03) |
| AC-6(9) | Log use of privileged functions | 4.3 | Root activity alarm. Fired on a real root session during testing. | [31-root-alarm-email.png](../screenshots/31-root-alarm-email.png), [30-root-alarm-investigation.png](../screenshots/30-root-alarm-investigation.png) | Implemented (tested) |
| AC-7 | Unsuccessful logon attempts | 4.6 | Alarm at 3 failed console logins in 5 minutes. Tested: 3 failures in 29 seconds, alarm 3 min 47 s after the first failure. AWS IAM has no native lockout, so this is detection only. | [34-failed-logins-query.png](../screenshots/34-failed-logins-query.png), [35-auth-failures-alarm-email.png](../screenshots/35-auth-failures-alarm-email.png) | Partial (detect only) |
| AC-12 | Session termination | n/a | Background root session found during investigation and closed. Procedure: sign out of root right after any root task. | [30-root-alarm-investigation.png](../screenshots/30-root-alarm-investigation.png) | Partial (R-06) |
| AU-2, AU-12 | Event logging, record generation | 3.1, 3.8, 3.9 | Multi-region trail, management events (read and write). S3 data events not enabled. | [06b-cloudtrail-config.png](../screenshots/06b-cloudtrail-config.png), [07-cloudtrail-after.png](../screenshots/07-cloudtrail-after.png) | Partial (R-05) |
| AU-3 | Content of audit records | n/a | Every record carries identity, time, source IP, user agent, request parameters and TLS details | [11-event-createtrail-json.png](../screenshots/11-event-createtrail-json.png) | Implemented |
| AU-5 | Response to logging failures | 4.5 | EventBridge rule alerts within a minute on `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`. Prowler marks CIS 4.5 failed because it only looks for a metric filter. | [26-tampering-alert-email.png](../screenshots/26-tampering-alert-email.png) | Compensating |
| AU-6 | Audit review and analysis | n/a | Event history review, CloudWatch Logs Insights queries used for two investigations | [10-event-createtrail.png](../screenshots/10-event-createtrail.png), [30-root-alarm-investigation.png](../screenshots/30-root-alarm-investigation.png), [34-failed-logins-query.png](../screenshots/34-failed-logins-query.png) | Implemented |
| AU-9 | Protection of audit information | 3.2, 3.3, 3.5, 2.1.1 | Log file validation (hourly digest files), private bucket, HTTPS-only bucket policy, versioning on. Logs use SSE-S3, not a customer managed KMS key. | [08-cloudtrail-s3-delivery.png](../screenshots/08-cloudtrail-s3-delivery.png), [43-log-bucket-hardened.png](../screenshots/43-log-bucket-hardened.png), [44-trail-status-verified.png](../screenshots/44-trail-status-verified.png) | Implemented (KMS gap R-04) |
| AU-11 | Audit record retention | n/a | CloudWatch Logs keeps 90 days for search and alerting. S3 keeps the long-term archive. | [19-cwlogs-retention.png](../screenshots/19-cwlogs-retention.png) | Implemented |
| CA-2 | Control assessments | n/a | Prowler baseline scan, remediation, rescan with the same scope | Prowler reports, README before/after table | Implemented |
| CA-7 | Continuous monitoring | 3.3, 4.16 | GuardDuty plus 8 live detections. AWS Config and Security Hub not enabled. | [13-guardduty-enabled.png](../screenshots/13-guardduty-enabled.png), [29-cloudwatch-alarm-overview.png](../screenshots/29-cloudwatch-alarm-overview.png) | Partial (R-09) |
| CM-2 | Baseline configuration | n/a | Detection layer defined as a CloudFormation template. Billing baseline captured before any build. | [detection-alerting.yaml](../cloudformation/detection-alerting.yaml), [03b-billing-baseline.png](../screenshots/03b-billing-baseline.png) | Implemented |
| CM-3 | Configuration change control | n/a | Template validated before deploy. Bucket policy backed up before change and verified after. Tampering rule flags changes to logging and GuardDuty. | [21-cfn-validate.png](../screenshots/21-cfn-validate.png), [27-tampering-updatedetector-email.png](../screenshots/27-tampering-updatedetector-email.png), [44-trail-status-verified.png](../screenshots/44-trail-status-verified.png) | Implemented |
| CM-8 | System component inventory | n/a | All stack resources tagged `Project=cloud-sec-lab`. Cost history reviewed. Leftover training resources found (4 buckets, 2 roles). | [04-cost-history.png](../screenshots/04-cost-history.png), Prowler report | Partial (POA&M-03) |
| IA-2(1) | MFA for privileged accounts | 1.5, 1.10, 4.2 | MFA on root and the IAM user (passkey). Alarm on console login without MFA. | [01-iam-security-recommendations.png](../screenshots/01-iam-security-recommendations.png), [33-mfa-passkey-prompt.png](../screenshots/33-mfa-passkey-prompt.png) | Implemented |
| IA-5(1) | Password-based authentication | 1.8, 1.9 | 14 character minimum, all four character types, 24 password history. Expiration left off on purpose per NIST SP 800-63B. | [42-password-policy-access-analyzer.png](../screenshots/42-password-policy-access-analyzer.png) | Implemented (deviation R-08) |
| IR-4 | Incident handling | n/a | GuardDuty response playbook. Attack sequence finding triaged and mapped to MITRE ATT&CK. | [ir-playbook-guardduty.md](ir-playbook-guardduty.md), [15-attack-sequence-overview.png](../screenshots/15-attack-sequence-overview.png), [16-attack-sequence-timeline.png](../screenshots/16-attack-sequence-timeline.png) | Implemented |
| IR-6 | Incident reporting | n/a | All alerts routed to one SNS topic with email delivery | [22-sns-subscription-confirmed.png](../screenshots/22-sns-subscription-confirmed.png) | Implemented |
| RA-5 | Vulnerability monitoring and scanning | n/a | Prowler configuration scanning, GuardDuty threat detection | Prowler reports, [14-guardduty-sample-summary.png](../screenshots/14-guardduty-sample-summary.png) | Implemented |
| SC-8 | Transmission confidentiality | 2.1.1 | `DenyInsecureTransport` on the log bucket. Older training buckets still allow HTTP. | [43-log-bucket-hardened.png](../screenshots/43-log-bucket-hardened.png) | Partial (POA&M-03) |
| SC-28 | Protection of information at rest | 3.5 | SSE-S3 on all buckets, default encryption on CloudWatch Logs. No customer managed KMS keys. | Prowler report | Accepted risk (R-04, R-10) |
| SI-4 | System monitoring | 4.1 to 4.4, 4.6, 4.10 | GuardDuty, 2 EventBridge rules, 6 CIS metric filters and alarms | [24-cfn-resources.png](../screenshots/24-cfn-resources.png) | Implemented |
| SI-4(5) | System-generated alerts | n/a | 5 of 5 tested detections delivered email alerts (under 1 minute for EventBridge, under 4 minutes for metric alarms) | [26](../screenshots/26-tampering-alert-email.png), [27](../screenshots/27-tampering-updatedetector-email.png), [28](../screenshots/28-guardduty-alert-email.png), [31](../screenshots/31-root-alarm-email.png), [35](../screenshots/35-auth-failures-alarm-email.png) alert screenshots | Implemented (tested) |

## Coverage summary

| Status | Count |
|---|---|
| Implemented | 19 |
| Partial | 7 |
| Compensating | 1 |
| Accepted risk | 1 |
| **Total controls mapped** | **28** |
