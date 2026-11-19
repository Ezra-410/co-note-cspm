# Milestone 1 — Co-note cloud environment: inventory and baseline

**Collected:** 2026-11-19 02:31 UTC · **By:** `conote-security-audit` (read-only) · **Raw evidence:** `reports/m1/m1-inventory-20261119-0231.txt` (kept locally, not committed)

## 1. Cloud provider, account and regions

| Item | Value |
|---|---|
| Cloud provider | Amazon Web Services (AWS) |
| Account | `093397426920` (AWS Free plan, created for this lab, 2026-11-17) |
| Primary region | **eu-west-1 (Ireland)**: all Co-note workloads |
| Other region in use | **us-east-1**: global services only (IAM is global and reported there; 1 billing "payments" record) |
| Regions enabled | 17 (default set; opt-in regions such as af-south-1 are not enabled) |
| Availability zone used | 1 (first AZ of eu-west-1: lab cost choice, no high availability) |

**Account → Region → Availability Zone:** the *account* is the security and billing boundary (who owns it, who pays). A *region* is a geographic location with its own copy of most services (eu-west-1 = Ireland). An *availability zone* is one or more separate data centres inside a region; spreading across AZs protects against a data-centre failure.

## 2. Resource inventory

Deployed with Terraform (`terraform/`, 70 resources), all tagged `Project=co-note, Environment=lab, Owner=ezra, ManagedBy=terraform`.

| Category | Resource | Identifier | Security-relevant state |
|---|---|---|---|
| **Compute** | EC2 `conote-app-01` (t3.micro, Amazon Linux 2023) | `i-0f3269d659872b2ba` | running · public IP `3.248.188.9` · **IMDSv2 required** · admin through SSM, no SSH key |
| **Storage** | S3 `conote-uploads-093397426920` | — | user files · 4/4 public-access-block ON · AES-256 · versioning · TLS-only |
| | S3 `conote-backups-093397426920` | — | backups · same controls |
| | S3 `conote-cloudtrail-093397426920` | — | audit logs · same controls |
| | S3 `conote-access-logs-093397426920` | — | S3 access logs · same controls · 90-day expiry |
| | EBS root volume (8 GB gp3) | `vol-0d634b98279a4177e` | **encrypted** · EBS encryption by default ON for the region |
| **Databases** | none (no RDS, no DynamoDB) | — | lab cost choice; documented limitation |
| **Networking** | VPC `conote-vpc` 10.20.0.0/16 | `vpc-0fc49d91d5b4e2277` | 1 public subnet `subnet-0f6925069b669361c` (no auto public IP) · flow logs (REJECT) → CloudWatch Logs |
| | **Default VPC** 172.31.0.0/16 (created by AWS) | `vpc-054ddc2a0ef918f06` | **3 subnets with auto-assign public IP = True** · unused · see risk R3 |
| | SG `conote-web-sg` | `sg-00e3f54ad1dd35ad6` | 80 + 443 from 0.0.0.0/0 (**intended** public web) |
| | SG `conote-admin-sg` | `sg-09824c64adf8aaacb` | **no inbound rule** (administration via SSM) |
| | SG `default` (conote VPC) | `sg-0aaf892237aad72b7` | no rules (locked by Terraform: CIS) |
| | SG `default` (default VPC) | `sg-0fede33b8a1f754fe` | allows all traffic from itself (AWS default) |
| **Identity** | IAM users | `Ezra`, `conote-security-audit` | see section 4 |
| | IAM roles (8, excl. service-linked) | `conote-security-audit`, `conote-cspm-remediator`, `conote-cspm-github`, `conote-app-host`, `conote-vpc-flow-logs`, + AWS-created | see section 4 |
| | GitHub OIDC provider | token.actions.githubusercontent.com | for scheduled scans (no stored keys) |
| **Logging & alerting** | CloudTrail `conote-trail` | — | multi-region · log-file validation · KMS-encrypted (`alias/conote-cloudtrail`, rotation ON) |
| | SNS `CoNote-CSPM-Alerts` | — | email subscription |
| | CloudWatch alarms (3) | Critical-Findings, Public-Exposure, Scan-Missing | Scan-Missing = ALARM: correct, no scan has run yet (see note) |
| | EventBridge rule `conote-cspm-risky-config-change` | — | real-time alert on SG/S3 exposure API calls |

> **Note:** `CoNote-CSPM-Scan-Missing` is in **ALARM** at baseline. This is the "monitor the monitor" alarm: no scan has published results yet, so missing data counts as a failure. It must turn **OK** once scheduled scans run (Milestone 6).

## 3. Initial public exposure assessment

| Check | Result | Assessment |
|---|---|---|
| Inbound rules open to 0.0.0.0/0 | only `conote-web-sg` tcp/80 and tcp/443 | **Intended**: the Co-note web front. No SSH/RDP/database port open. |
| Instances with public IP | `conote-app-01` (3.248.188.9) | **Intended**, tagged `Exposure=public-intended`; only 80/443 reachable |
| S3 bucket-level public access block | 4/4 settings ON on all 4 buckets | compliant |
| S3 bucket policy public? | `IsPublic = False` on all 4 buckets | compliant |
| S3 **account-level** public access block | **not configured** (`NoSuchPublicAccessBlockConfiguration`) | **Accepted lab exception EXC-L01**: left off so the drift exercise can create a real exposure; each bucket has its own block |
| Default VPC subnets | auto-assign public IP = True | **Risk R3**: anything launched there by mistake becomes internet-facing |

> An error from `get-public-access-block` (like 5b) does **not** prove a resource is public. It only says the guard rail is missing. Real exposure needs the policy/ACL check (`IsPublic`) too.

**Baseline:** no unintended public exposure; one intended public service.

## 4. Identities and permissions

| Identity | Type | Permissions | MFA | Access keys | Used for |
|---|---|---|---|---|---|
| root | account owner | everything | **ON** | **none** | billing only |
| `Ezra` | IAM user (human) | AdministratorAccess, SecurityAudit, IAMUserChangePassword + inline `CoNote-CSPM-Remediation` | ON (`mfa/Redmi`) | 1 active (created 2026-11-18) | Terraform, administration, approving remediation |
| `conote-security-audit` | IAM user (program) | SecurityAudit, ViewOnlyAccess + inline `cspm-read-additions` (extra reads + metrics in CoNote/CSPM & CloudMaid only) | n/a (no console) | 1 active | **all security assessments** |
| `conote-cspm-remediator` | role | revoke SG ingress / restore S3 public block on co-note resources only | **required to assume** | none (temporary) | controlled remediation |
| `conote-cspm-github` | role (OIDC) | same as auditor | n/a | none (temporary) | scheduled scans, `main` branch only |
| `conote-security-audit` | role | same as auditor | n/a | none | created by Terraform; unused while the auditor is a user (kept for comparison) |
| `conote-app-host` | role (EC2) | AmazonSSMManagedInstanceCore | n/a | none | lets the server be managed through SSM |
| `conote-vpc-flow-logs` | role (service) | write to one log group | n/a | none | VPC flow logs |

**Identity findings:**
- **I-1 (low):** `Ezra` has `SecurityAudit` and `CoNote-CSPM-Remediation` on top of `AdministratorAccess`. They're redundant (admin already allows everything) and blur the separation of duties. Remove them; remediation goes through the MFA-protected role.
- **I-2 (medium):** `conote-security-audit` uses a long-lived access key. Rotate every 90 days or replace it with the role (short-lived sessions).
- **I-3 (incident, closed):** two access keys were exposed in a chat during setup on 2026-11-18. Both were deactivated and deleted within minutes, new keys issued, CloudTrail reviewed. CLI credentials were also stored on a Windows path (`/mnt/c`, permissions not enforceable). They were moved to `~/.aws` with permissions 700/600.

## 5. Security assessment identity

`conote-security-audit` was tested on 2026-11-19 (screenshots M1-*):

| Test | Result |
|---|---|
| `sts get-caller-identity` | `user/conote-security-audit` ✅ |
| read EC2 security groups | allowed ✅ |
| publish metric in `CoNote/CSPM` | allowed ✅ |
| publish metric in another namespace | **AccessDenied** ✅ |
| `s3:CreateBucket` | **AccessDenied** ✅ |
| `ec2:CreateSecurityGroup` | **UnauthorizedOperation** ✅ |

It can see everything and change nothing.

## 6. Resources to monitor continuously

| Priority | Resource | Why | Main checks |
|---|---|---|---|
| 1 | Security groups (`conote-web-sg`, `conote-admin-sg`, defaults) | network entry points | no admin ports to 0.0.0.0/0; admin SG stays empty |
| 1 | S3 buckets (uploads, backups) | user data and backups | public access block 4/4, no public policy, encryption, versioning |
| 1 | IAM users, keys, root | account takeover path | MFA, key age < 90 days, no root keys, least privilege |
| 2 | EC2 `conote-app-01` | public service | IMDSv2, encrypted disk, only intended ports, patching |
| 2 | CloudTrail + its bucket and KMS key | audit trail must not be switched off | trail on, multi-region, validation, bucket private |
| 2 | Default VPC | unused but launch-ready with public IPs | no resources launched in it (or delete it) |
| 3 | SNS topic, alarms, EventBridge rule | the alerting chain itself | subscription confirmed, alarms present |
| 3 | Tags | ownership and scope of remediation | Project/Owner/Environment present |

## 7. Risks found at baseline

| ID | Risk | Severity | Decision |
|---|---|---|---|
| R1 | Account-level S3 public access block off | Medium | Accepted for the lab (EXC-L01), expires 2026-12-31 |
| R2 | Single AZ, no database, no backups of the instance | Low (lab) | Documented limitation |
| R3 | Default VPC with public-IP subnets | Medium | Monitor; recommend deletion after the lab |
| R4 | Redundant policies on `Ezra` (I-1) | Low | Fix in Milestone 3 cleanup |
| R5 | Auditor uses a long-lived key (I-2) | Medium | Rotation every 90 days |

---

## 8. Investigation questions

**1. Account vs region vs availability zone?**
The **account** is your "house": everything you own, who can enter, who pays. A **region** is a **city** where AWS has data centres (Ireland = eu-west-1). An **availability zone** is one **building** in that city with its own power and network. Co-note uses one account, one region, one AZ.

**2. Why is inventory important for security?**
You can't protect what you don't know exists. A forgotten server or bucket is never patched or checked, and attackers love it. The inventory is the list every scanner and every alert is measured against. Here it even revealed the **default VPC**, which we never created.

**3. Can a resource be public even if its VM isn't?**
Yes. An S3 bucket, a database snapshot, or a load balancer can be reachable from the internet with **no virtual machine involved at all**. Public exposure must be checked per resource type, not just on servers.

**4. Public IP vs public access to a service?**
A **public IP** is like a house having a **street address**. **Public access** means the **door is actually unlocked**. `conote-app-01` has a public IP, but only ports 80/443 are open, so SSH isn't reachable even though the address is public. Without a public IP, a service can still be public through a load balancer.

**5. Why should the assessment identity be read-only?**
- A scanner only needs to **look**.
- If its key is stolen (like ours almost was), the thief can see but can't change or delete anything.
- It also guarantees that a scan never modifies production by mistake.

**6. What if the assessment can't access some services?**
Those resources become **blind spots**. "No finding" then means "not checked", **not** "secure". The tool must report AccessDenied as *not assessed*, and the report must list what wasn't covered. That's why our auditor got Prowler's extra read permissions.

**7. How to find resources created outside the normal process?**
- Compare **what Terraform says should exist** with **what actually exists** (inventory, `terraform plan` drift).
- Look for resources **without the `ManagedBy=terraform` tag**.
- Read **CloudTrail** to see who created what, and whether it was a person or the pipeline.
- Our EventBridge rule and Custodian checks catch these changes automatically.

**8. Intended vs actual configuration?**
- **Intended** = the plan: Terraform code reviewed in the pipeline.
- **Actual** = what is really running right now in AWS.
- They differ when someone changes things by hand (console, CLI) or when something fails halfway. That gap is called **drift**, and finding it is the whole purpose of CSPM. In the final challenge we create drift on purpose and catch it.
