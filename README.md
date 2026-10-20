# Cloud Security Labs

Hands-on AWS and DevSecOps security labs, built as infrastructure-as-code.

Each lab solves a real cloud security problem end to end: the threat, the design, the Terraform that builds it, how to test it, and how to tear it down. Everything here is written to run in a personal AWS sandbox account.

## Labs

| # | Lab | Focus | Status |
|---|-----|-------|--------|
| 01 | [IAM Least Privilege & MFA Enforcement](labs/01-iam-least-privilege/) | Identity, permission boundaries, MFA | ✅ Ready |
| 02 | [Threat Detection with CloudTrail & GuardDuty](labs/02-threat-detection/) | Logging, detection, alerting | ✅ Ready |
| 03 | [Secure VPC Design](labs/03-secure-vpc/) | Network segmentation, flow logs | 🛠 Planned |

## Skills demonstrated

- **Identity & access:** IAM roles and policies, least privilege, permission boundaries, MFA enforcement
- **Detection & response:** CloudTrail, GuardDuty, EventBridge, SNS alerting
- **Network security:** VPC segmentation, security groups, NACLs, VPC Flow Logs
- **DevSecOps:** Terraform, automated IaC scanning (Checkov) and secret scanning (Gitleaks) in GitHub Actions

## Repo layout

```
cloud-security-labs/
├── labs/                  # One folder per lab
│   └── NN-lab-name/
│       ├── README.md      # Problem, design, steps, testing, cleanup
│       └── terraform/     # Infrastructure-as-code for the lab
├── templates/             # Starting template for new labs
└── .github/workflows/     # Automated security scanning on every push
```

## Running a lab

Prerequisites: an AWS account you control (ideally a dedicated sandbox), the [AWS CLI](https://aws.amazon.com/cli/) configured with a profile, and [Terraform](https://developer.hashicorp.com/terraform/install) 1.5+.

```bash
cd labs/01-iam-least-privilege/terraform
cp terraform.tfvars.example terraform.tfvars   # edit with your own values
terraform init
terraform plan
terraform apply
# ...test...
terraform destroy
```

## Safety

- No credentials, account IDs or state files are committed. `.gitignore` blocks them and CI scans every push for leaked secrets.
- Labs are designed to stay within or close to the AWS Free Tier. Always run `terraform destroy` when finished. GuardDuty has a 30-day free trial, then charges.
- Use a sandbox account, never a production one.

## Author

**Abirami Pandian** · Network Security / Cloud Security Engineer · Newcastle upon Tyne, UK
