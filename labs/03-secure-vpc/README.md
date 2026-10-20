# Lab 03: Secure VPC Design (planned)

## The problem
Flat networks let an attacker who compromises one server reach everything else. Exposed management ports (SSH/RDP open to `0.0.0.0/0`) are among the most common cloud misconfigurations.

## Planned design
- VPC with **public, private and isolated** subnets across two Availability Zones
- Internet-facing load balancer only in public subnets; app servers in private subnets with **no public IPs**
- Database tier in isolated subnets with no internet route at all
- **Security groups** referencing each other (app → DB) instead of IP ranges
- **NACLs** as a second, stateless layer
- **VPC Flow Logs** to CloudWatch for investigation and GuardDuty
- **SSM Session Manager** instead of SSH bastions: no inbound ports, every session logged
- **VPC endpoints** for S3 so traffic never crosses the internet

## Skills it will show
Network segmentation and defence in depth, applying firewall experience (Palo Alto, Fortinet, Juniper SRX) to cloud-native controls.

Status: 🛠 to be built.
