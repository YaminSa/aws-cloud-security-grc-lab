# Incident Response Playbook: GuardDuty High and Critical Findings

**Scope:** Single AWS account, us-east-1
**Owner:** Yamin Salahi
**Framework:** NIST SP 800-61 (incident handling lifecycle), NIST 800-53 IR-4, IR-6
**Last tested:** Oct 4, 2026 (sample finding delivered by email in about 1 minute)

## 1. Trigger

The EventBridge rule `guardduty-high-critical-findings` matches any GuardDuty finding with severity 7.0 or higher and sends an email through the `cloud-sec-lab-alerts` SNS topic.

Example alert:

```
[GuardDuty] Severity 8 | UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS | us-east-1 | Credentials for instance role ... were used from an external IP address. | Finding ID: 687106cb...
```

## 2. Response targets

| Severity | GuardDuty score | Acknowledge within | Example |
|---|---|---|---|
| Critical | 9.0 to 10.0 | 15 minutes | Attack sequence: compromised credentials |
| High | 7.0 to 8.9 | 1 hour | EC2 role credentials used outside AWS |
| Medium | 4.0 to 6.9 | 1 business day | Unusual API call pattern |
| Low | 1.0 to 3.9 | Weekly review | Port probe on a closed port |

Only High and Critical send an email. Medium and Low are reviewed in the GuardDuty console.

## 3. Detection and analysis

Answer these five questions before taking action. Write the answers in the ticket.

1. **What happened?** Read the finding type and title. Open the finding and read every signal, not just the headline.
2. **Which identity or resource?** Note the user or role, the access key ID, and the resource ARNs.
3. **Is it real?** Check the source IP, user agent and timing against known activity. Was this me, an approved change, or a test?
4. **How far did it get?** Map the signals to MITRE ATT&CK tactics. Persistence or defense evasion means the attacker is settling in.
5. **What else did this credential do?** Pull its full history from CloudTrail (query below).

### CloudTrail query: everything one access key did

Run in CloudWatch Logs Insights against `cloudtrail/cloud-sec-lab`:

```
fields eventTime, eventName, eventSource, sourceIPAddress, userAgent, errorCode
| filter userIdentity.accessKeyId = "ACCESS_KEY_ID_FROM_FINDING"
| sort eventTime asc
| limit 500
```

### CloudTrail query: persistence and evasion actions

```
fields eventTime, eventName, userIdentity.arn, sourceIPAddress
| filter eventName in ["CreateUser","CreateAccessKey","CreateRole","AttachRolePolicy","PutRolePolicy","AttachUserPolicy","UpdateAssumeRolePolicy","StopLogging","DeleteTrail","UpdateTrail","DeleteDetector","UpdateDetector"]
| sort eventTime asc
```

Use `eventTime`, not `@timestamp`. The second one is when CloudWatch received the event, which can be a few minutes later.

## 4. Containment

Pick the steps that match the identity involved. **[CLOUDSHELL]** for all commands.

**Compromised IAM user**

```bash
# Block every action by this user right away
aws iam put-user-policy --user-name USER --policy-name IR-DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# Turn off every access key the user has
aws iam list-access-keys --user-name USER
aws iam update-access-key --user-name USER --access-key-id KEY_ID --status Inactive
```

A deny policy beats any allow, so this stops the user even if the attacker attached admin policies. Keys are deactivated, not deleted, so the evidence stays intact.

**Compromised IAM role (for example EC2 instance credentials)**

In the IAM console, open the role, go to **Revoke sessions**, and click **Revoke active sessions**. This attaches a policy that denies anything signed with credentials issued before that moment. New sessions still work, so fix the source (the instance) next.

**Logging was turned off**

```bash
aws cloudtrail start-logging --name cloud-sec-lab-trail
aws cloudtrail get-trail-status --name cloud-sec-lab-trail --query '{Logging:IsLogging,Error:LatestDeliveryError}'
```

Do this first if the tampering alert also fired. Without logs, nothing after this point can be investigated.

## 5. Eradication

- Delete any users, roles, access keys or policies the attacker created (from the persistence query).
- Detach policies the attacker attached.
- Check for new resources in every region (EC2 instances, Lambda functions, Bedrock usage).
- Rotate the credentials of the affected identity.

## 6. Recovery

- Remove the `IR-DenyAll` policy only after eradication is confirmed.
- Confirm CloudTrail is logging and GuardDuty is enabled.
- Watch the identity closely for 7 days.
- Check Cost Explorer for spend spikes (crypto mining, model abuse).

## 7. Post-incident

- Write a timeline from `eventTime` values.
- Record root cause and which control failed or was missing.
- Update the risk register and POA&M.
- Archive the GuardDuty finding with a note explaining the outcome.

## Worked example: attack sequence (sample finding, Oct 2, 2026)

**Finding:** `AttackSequence:IAM/CompromisedCredentials`, Critical, 5 correlated signals, all from one temporary key (`ASIA...EXAMPLE`) belonging to `IAMUser/john_doe`.

| # | Signal | MITRE tactic | Technique |
|---|---|---|---|
| 1 | `CreateRole` from a Tor exit node | Privilege Escalation, Persistence | T1098.003 Additional Cloud Roles |
| 2 | `DeleteTrail` from a Kali Linux host | Defense Evasion | T1562.008 Disable or Modify Cloud Logs |
| 3 | `AttachRolePolicy` from a Kali Linux host | Persistence | T1098 Account Manipulation |
| 4 | CloudTrail trail disabled | Defense Evasion | T1562.008 Disable or Modify Cloud Logs |
| 5 | Anomalous Bedrock model invocation (cost harvesting) | Impact | T1496 Resource Hijacking |

**Assessment:** A stolen session key used through Tor and attacker tooling. The attacker built a backdoor role that would survive key revocation, attacked logging twice to blind defenders, then used the account's AI service. Two of five signals target logging, which is why the tampering alert exists in this lab.

**Response under this playbook:**

1. Contain: `IR-DenyAll` on john_doe, deactivate the key, revoke sessions on the new role.
2. Restore logging with `start-logging` and confirm.
3. Eradicate: delete the attacker's role and its attached policy.
4. Recover: rotate john_doe's credentials, review Bedrock usage and billing.
5. Lessons learned: real-time alerting on `DeleteTrail` and `StopLogging` (built in Phase 3 and tested).

**Analyst note:** This finding was confirmed as sample data, not a real incident. The "Tor exit node" IP was `10.0.0.1`, a private address that can't be a Tor node. All five signals shared one timestamp, and the Bedrock ARN used AWS's placeholder account `123456789012`. Checking evidence before trusting an alert title is part of triage.
