# Lab 02: Threat Detection with CloudTrail & GuardDuty

## The problem
You can't respond to what you can't see. Many AWS incidents go unnoticed for weeks because API activity isn't logged, nobody watches the logs, or an attacker quietly switches logging off.

This lab builds a small, real detection pipeline: **record everything, detect threats automatically, and alert a human within minutes.**

## Architecture

```
 All AWS API calls ──► CloudTrail (multi-region) ──► S3 log bucket
                              │                     (encrypted, validated,
                              │                      90-day retention)
                              ▼
                        GuardDuty  ◄── also analyses VPC Flow Logs + DNS
                              │
                              ▼
                        EventBridge rules ──► SNS topic ──► 📧 your email
                          • GuardDuty finding ≥ Medium
                          • Root user console sign-in
                          • CloudTrail stopped / deleted / changed
```

## What you'll learn
- Setting up an organisation-grade CloudTrail: multi-region, log file validation, a locked-down bucket policy
- Enabling GuardDuty and reading its findings
- Writing EventBridge event patterns to turn raw events into alerts
- Detecting defence evasion (MITRE ATT&CK T1562.008: disabling cloud logs)

## Prerequisites
- AWS sandbox account with an admin CLI profile (default name: `sandbox`)
- Terraform 1.5+
- An email address for alerts

## Deploy
```bash
cd labs/02-threat-detection/terraform
cp terraform.tfvars.example terraform.tfvars   # set alert_email
terraform init
terraform apply
```
**Then check your inbox and click the SNS confirmation link.** No alerts arrive until you do.

## Test it

1. **Generate sample GuardDuty findings.** These are clearly labelled fakes, safe to create:
   ```bash
   DETECTOR=$(terraform output -raw guardduty_detector_id)
   aws guardduty create-sample-findings --detector-id "$DETECTOR" \
     --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" \
     --profile sandbox --region eu-west-2
   ```
   ✅ An alert email arrives within a few minutes. Open GuardDuty in the console to see the finding details.

2. **Simulate an attacker hiding their tracks.**
   ```bash
   aws cloudtrail stop-logging --name lab02-trail --profile sandbox --region eu-west-2
   ```
   ✅ A tampering alert email arrives. Turn logging back on straight away:
   ```bash
   aws cloudtrail start-logging --name lab02-trail --profile sandbox --region eu-west-2
   ```

3. **Look at the raw evidence.** Open CloudTrail → Event history and filter on `StopLogging`. You'll see who did it, from which IP, and when. This is what an investigator works from.

4. **Validate log integrity.**
   ```bash
   aws cloudtrail validate-logs --trail-arn <trail-arn> --start-time 2026-01-01T00:00:00Z \
     --profile sandbox --region eu-west-2
   ```

**Root login alert note:** AWS delivers root console sign-in events in **us-east-1**. To catch them, deploy this lab with `aws_region = "us-east-1"`, or add a copy of that rule there.

## Cost
- CloudTrail: the first management-event trail is free; S3 storage is pennies.
- **GuardDuty: 30-day free trial, then charged by volume.** For a quiet sandbox that's usually a few pounds a month, but **destroy the lab** if you aren't using it.
- SNS email and EventBridge: free at this volume.

## Clean up
```bash
terraform destroy
```

## Real-world notes
- In production, CloudTrail goes to a **separate, locked-down log archive account** so a compromised workload account can't delete its own evidence. AWS Control Tower sets this up.
- Alerts would usually go to a SIEM (Splunk, Sentinel) or a ticketing/on-call tool rather than email. EventBridge can target those too.
- **GuardDuty findings map to MITRE ATT&CK**, which helps with triage and reporting.
