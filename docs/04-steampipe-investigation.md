# Milestone 4 — Steampipe: cloud inventory and security queries

**Run:** 2026-11-22 22:07 UTC · **Identity:** profile `conote-audit` (read-only) · **Scope:** account 093397426920, eu-west-1
**Queries:** `steampipe/queries/01–04*.sql` · **Runner:** `scripts/run-queries.sh` · **Raw results:** `reports/m4/m4-queries-20261122-2207.txt`

## 1. Installation and configuration

| Item | Value |
|---|---|
| Steampipe | v2.5.1 (official install script) |
| AWS plugin | **installed manually** as `local/aws`. `steampipe plugin install aws` failed repeatedly on an unstable link (connection reset / HTTP/2 PROTOCOL_ERROR / unexpected EOF): it downloads the whole OCI package, Mac builds included. Only the `linux_amd64` layer (80.7 MB) was fetched from `ghcr.io` with a resumable `curl -C -`, its **sha256 verified against the registry digest** `276b98cb…911f`, and unpacked to `~/.steampipe/plugins/local/aws/aws.plugin`. |
| CSV plugin | 1.3.0: reads `data/*.csv` (Prowler results, history) and `registers/*.csv` (findings, remediation, exceptions) |
| Connection `aws` | `plugin = "local/aws"`, `profile = "conote-audit"`, `regions = ["eu-west-1"]` |
| Runner | Steampipe v2 rejects several statements in one call (`cannot insert multiple commands into a prepared statement`). `run-queries.sh` splits each file and runs one statement per call, titled, and appends to a timestamped file. |

## 2. Cloud resource inventory (query file 01)

| Query | Result |
|---|---|
| S3 buckets | **4**: `conote-access-logs`, `conote-backups`, `conote-uploads`, `conote-cloudtrail` (all `-093397426920`, eu-west-1) |
| EC2 instances | **1**: `i-0f3269d659872b2ba` t3.micro, running, public IP 3.248.188.9 |
| Security groups | **4**: `conote-web-sg`, `conote-admin-sg`, `default` (conote VPC), `default` (default VPC `vpc-054ddc2a0ef918f06`) |
| Tagged resources by service | ec2 13 · s3 4 · cloudwatch 3 · logs 1 · cloudtrail 1 · sns 1 · events 1 · kms 1 = **25** |
| By environment tag | `lab` = 25 |

The tagging API only lists resources that carry tags, so it shows **what Terraform built**. AWS-created resources (default VPC, its subnets and security group) are absent from it. Query 04 catches them.

## 3. Investigation results (Step 9)

| # | Query | Affected | Resource(s) | Account / region | Configuration responsible | Requirement | Remediation |
|---|---|---|---|---|---|---|---|
| Q1 | Bucket **policy** public | **0** | — | 093397426920 / eu-west-1 | no policy grants `Principal: *` (only TLS-deny and service statements) | CIS 2.1.4 · NIST AC-3 | none needed |
| Q2 | Public access block incomplete | **0** | all 4 buckets 4/4 ON | idem | Terraform `aws_s3_bucket_public_access_block` on every bucket | CIS 2.1.4 · NIST AC-3/AC-21 | none needed. **Note:** account-level block is OFF (EXC-L01), so this query does not see it. |
| Q3 | Admin ports open to internet | **0** | — | idem | `conote-admin-sg` has no ingress since CHG-001 (SSH removed 2026-11-19) | CIS 5.2/5.3 · NIST SC-7/AC-17 | none needed |
| Q4 | Buckets without default encryption | **0** | all AES-256 | idem | `aws_s3_bucket_server_side_encryption_configuration` | NIST SC-28 | optional: SSE-KMS (accepted EXC-L06) |
| Q5 | Buckets without versioning | **0** | all versioned | idem | `aws_s3_bucket_versioning` | NIST CP-9/SI-7 | none needed |
| Q6 | Unencrypted EBS volumes | **0** | `vol-0d634b98279a4177e` encrypted | idem | `encrypted = true` + EBS encryption by default | CIS 2.2.1 · NIST SC-28 | none needed |
| Q7 | **Instances reachable from the internet** (join instance ⨝ SG rules) | **1 instance, 2 paths** | `conote-app-01` 3.248.188.9 via `sg-00e3f54ad1dd35ad6` tcp/80 and tcp/443 | idem | public IP + `conote-web-sg` allows 0.0.0.0/0 | NIST SC-7 | **intended** (tag `Exposure=public-intended`, EXC-L04). Production: HTTPS only, ALB + WAF, redirect 80 at the load balancer |
| Q8 | IAM users and MFA | **1 without MFA** | `conote-security-audit` (`mfa_enabled=false`, never logged in) | global | programmatic user, **no console password** | CIS 1.10 · NIST IA-2(1) | **false positive in context**: MFA protects console logins; risk is the long-lived key (F-04): rotate / replace by role |
| Q9 | Resources missing required tags | **1** | `sg-0fede33b8a1f754fe` (default SG of the **default VPC**) | eu-west-1 | created by AWS, not by Terraform: no `Project/Owner/Environment` | NIST CM-8 | delete the unused default VPC, or tag it and keep it empty (risk R3) |

**Summary:** no unintended exposure, no encryption or versioning gap. The only issues are the **default VPC** (untagged, launch-ready with public IPs) and the auditor's **long-lived key**. Both were already known from M1/M2: three tools (CLI inventory, Prowler, Steampipe) agree.

## 4. Before vs now

On 2026-11-19 08:28–08:35 UTC, Q3 would have returned `sg-09824c64adf8aaacb tcp 22 0.0.0.0/0` (drift, then remediated with CHG-001). Today it returns 0. Keeping these result files is what makes this comparison possible.

## 5. Limitations
- Only eu-west-1 is queried (`regions = [...]`). Resources in other regions are invisible to these queries.
- Q2 checks **bucket-level** blocks only. Account-level and access-point policies need other tables (`aws_s3_account_settings`, `aws_s3_access_point`).
- Steampipe shows the configuration **now**. Without saved results there is no history (hence `reports/m4/` and the dashboard trend in M5).
- Results depend on the auditor's permissions. A denied API call returns an error or empty rows, never "secure".

---

## 6. Investigation questions

**1. Querying a cloud API vs a normal database?**
- A normal database **stores** the data. You query a copy that someone saved earlier.
- Steampipe stores almost nothing: each query **calls AWS live** (`DescribeInstances`, `ListBuckets`…) and turns the answer into rows.
- So results are always current, but slower and limited by API rate limits and permissions.

**2. What is a Steampipe plugin?**
A translator for one service. The **AWS plugin** knows which AWS API to call for each table and how to turn the JSON answer into columns. The **CSV plugin** does the same for our files. Ours was installed by hand, then checked with its sha256 fingerprint.

**3. How are cloud resources shown as tables?**
Each **resource type is a table** (`aws_s3_bucket`, `aws_ec2_instance`), each **resource is a row**, and each **setting is a column** (`versioning_enabled`, `public_ip_address`). Nested settings like tags or rules become JSON columns (`tags ->> 'Owner'`).

**4. Why SQL for security investigations?**
Everyone in IT already knows it, and it can **filter** (`WHERE block_public_acls = false`), **count**, **group** and above all **join** resources together. One query answers *"which servers are reachable from the internet and why?"*, where the console would need ten clicks across several pages.

**5. Can one SQL query find every public exposure risk?**
No. Exposure comes from many places:
- bucket policies, ACLs and access points
- security groups, network ACLs and route tables
- load balancers, API gateways
- public snapshots, Lambda URLs, shared AMIs, IAM trust policies…

And one query only sees the tables and regions it reads. You need a **set** of queries plus tools like Prowler.

**6. Public bucket policy vs incomplete public access block?**
- A **public bucket policy** is an **open door**: the bucket really says "anyone may read".
- An **incomplete public access block** is a **missing lock**: nothing is open yet, but nothing stops someone opening it.

The first is an exposure; the second is a weakness. In the final challenge we'll create both.

**7. Can a resource be reachable through another resource even if its own settings look secure?**
Yes:
- a private server behind a **public load balancer**
- a private bucket readable by a **role** that a public Lambda can use
- a private database reachable from a public server in the same security group

That's why we **join** resources instead of checking each one alone.

**8. How to correlate resources with SQL joins?**
Match the ID one resource stores about another. Our Q7 joins each instance's `security_groups[].GroupId` with `aws_vpc_security_group_rule.group_id`. Result: `conote-app-01` is reachable **only** through ports 80 and 443 of `conote-web-sg`.

**9. What if the identity can't access a resource?**
The query returns an **error or missing rows** for it. An empty result can then mean "secure" **or** "not allowed to look". Always check that the identity has the needed permissions (our auditor has SecurityAudit + ViewOnlyAccess + extras) and read the error lines.

**10. Why keep query results over time?**
A query shows only **now**. Saved results show **change**: on 19 Nov port 22 was open, today it's closed. They let you measure how long a problem lasted, prove when it was fixed, spot problems that come back, and feed the dashboard's trend charts. Auditors also ask for this evidence.
