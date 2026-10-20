# Lab 01: IAM Least Privilege & MFA Enforcement

## The problem
Over-permissioned identities are behind a large share of cloud breaches. A typical failure: an analyst account gets broad S3 access "to save time", has no MFA, and its password is phished. The attacker now reads every bucket in the account, and can sometimes grant themselves more access.

This lab builds an identity that can do **exactly one job** and nothing else, even if it's compromised or misconfigured later.

## Architecture

```
            ┌──────────────────────────────┐
            │ Permission boundary          │  ← hard ceiling: read one bucket,
            │  ┌────────────────────────┐  │    manage own MFA, no escalation
 lab01-     │  │ Group: lab01-analysts  │  │
 analyst ──►│  │ Policy: read reports   │──┼──► S3: lab01-reports-xxxx
 (user)     │  │ bucket IF MFA present  │  │      (private, encrypted,
            │  └────────────────────────┘  │       versioned)
            └──────────────────────────────┘
```

Three layers of control:

1. **Group-based permissions.** The policy is attached to a group, not the user. Access is managed by membership, which scales and is easy to audit.
2. **MFA condition.** The analyst can read the bucket only when `aws:MultiFactorAuthPresent` is true. Without MFA, everything except setting up MFA is explicitly denied.
3. **Permission boundary.** The maximum permissions the user can ever have. If someone later attaches `AdministratorAccess` to this user by mistake, the boundary still caps them to reading one bucket. It also blocks privilege-escalation actions like creating policies or access keys.

## What you'll learn
- Writing least-privilege IAM policies with Terraform
- Enforcing MFA with IAM condition keys
- How permission boundaries limit the blast radius of mistakes and compromise
- Effective permissions = identity policy ∩ boundary (minus any explicit deny)

## Prerequisites
- AWS sandbox account with an admin CLI profile (default name: `sandbox`)
- Terraform 1.5+

## Deploy
```bash
cd labs/01-iam-least-privilege/terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

## Test it

1. **Give the analyst a console password.** In the IAM console, open `lab01-analyst` → Security credentials → Enable console access.
2. **Sign in as the analyst without MFA.** Open S3 and try the reports bucket. ❌ *Access denied*: the MFA condition is working.
3. **Set up MFA.** Still signed in as the analyst, assign a virtual MFA device (an authenticator app). This is allowed even without MFA, so users can enrol themselves.
4. **Sign out and back in with MFA.** Open the reports bucket and download `reports/q3-summary.txt`. ✅ *Allowed.*
5. **Try anything else,** such as listing other buckets or opening EC2. ❌ *Denied*: least privilege.
6. **Simulate a mistake.** As your admin, attach `AdministratorAccess` directly to `lab01-analyst`. Sign in as the analyst again and try EC2 or IAM. ❌ *Still denied*: the permission boundary caps them. Detach the policy afterwards.

You can also check decisions without signing in, using the [IAM Policy Simulator](https://policysim.aws.amazon.com/).

## Cost
Free. IAM is free, and the S3 bucket holds one tiny file.

## Clean up
```bash
terraform destroy
```
If you added a console password or MFA device manually, Terraform removes them too (`force_destroy = true` on the user).

## Real-world notes
- In production, human access usually comes through **IAM Identity Center (SSO)** with an identity provider such as Entra ID or Okta, rather than IAM users. The same principles apply: groups, MFA and boundaries.
- Permission boundaries are especially useful when **delegating** IAM administration, for example letting developers create their own roles without being able to exceed their own access.
- Review access regularly with **IAM Access Analyzer** and last-accessed data to remove unused permissions.
