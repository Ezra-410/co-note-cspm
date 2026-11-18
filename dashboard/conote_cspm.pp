# =============================================================================
# Co-note CSPM dashboard (Milestone 5)
# Data sources:
#   aws.*                    LIVE cloud configuration (Steampipe AWS plugin)
#   csv.prowler_findings     latest Prowler assessment (scripts/prowler-scan.sh)
#   csv.scan_history         one line per Prowler scan (trend)
#   csv.exposure_history     one line per 15-min exposure check (trend)
#   csv.findings_register    remediation tracking (registers/findings_register.csv)
# The dashboard is a VIEW, not the source of truth: raw reports stay in
# reports/ and the cloud APIs remain queryable.
# =============================================================================

dashboard "conote_cspm" {
  title = "Co-note · Cloud Security Posture"
  tags = {
    service = "AWS"
    type    = "Dashboard"
  }

  text {
    value = "Live configuration from AWS (Steampipe) + latest Prowler assessment + remediation register. **Check the scan date below before trusting the numbers.**"
  }

  container {
    card {
      width = 4
      sql   = <<-EOQ
        select 'Last Prowler scan (UTC)' as label,
               coalesce(max(scan_time), 'NO SCAN DATA') as value,
               case when max(scan_time) is null
                      or max(scan_time)::timestamptz < now() - interval '26 hours'
                    then 'alert' else 'info' end as type
        from csv.scan_history
      EOQ
    }
    card {
      width = 4
      sql   = <<-EOQ
        select 'Last exposure check (UTC)' as label,
               coalesce(max(scan_time), 'NO DATA') as value,
               case when max(scan_time) is null
                      or max(scan_time)::timestamptz < now() - interval '1 hour'
                    then 'alert' else 'info' end as type
        from csv.exposure_history
      EOQ
    }
  }

  # ---------------------------------------------------------------- Section A
  container {
    title = "A · Cloud security overview"

    card {
      width = 2
      sql   = <<-EOQ
        with r as (
          select arn from aws_tagging_resource
          union select arn from aws_vpc_security_group
          union select arn from aws_s3_bucket
          union select arn from aws_ec2_instance
          union select arn from aws_ebs_volume
          union select arn from aws_vpc
          union select arn from aws_iam_user
          union select arn from aws_iam_role where path <> '/aws-service-role/'
        )
        select 'Cloud resources' as label, count(*) as value, 'info' as type from r
      EOQ
    }
    card {
      width = 2
      sql   = <<-EOQ
        select 'Security findings (FAIL)' as label, count(*) as value,
               case when count(*) > 0 then 'alert' else 'ok' end as type
        from csv.prowler_findings where status = 'FAIL'
      EOQ
    }
    card {
      width = 2
      sql   = <<-EOQ
        select 'Critical findings' as label, count(*) as value,
               case when count(*) > 0 then 'alert' else 'ok' end as type
        from csv.prowler_findings where status = 'FAIL' and severity = 'Critical'
      EOQ
    }
    card {
      width = 2
      sql   = <<-EOQ
        select 'High findings' as label, count(*) as value,
               case when count(*) > 0 then 'alert' else 'ok' end as type
        from csv.prowler_findings where status = 'FAIL' and severity = 'High'
      EOQ
    }
    card {
      width = 2
      sql   = <<-EOQ
        select 'Non-compliant resources' as label, count(distinct resource_uid) as value,
               case when count(*) > 0 then 'alert' else 'ok' end as type
        from csv.prowler_findings where status = 'FAIL'
      EOQ
    }
    card {
      width = 2
      query = query.public_exposure_count
    }

    chart {
      title = "Prowler FAIL findings by severity (trend)"
      type  = "line"
      width = 6
      sql   = <<-EOQ
        select scan_time, critical::int as critical, high::int as high, medium::int as medium
        from csv.scan_history order by scan_time
      EOQ
    }
    chart {
      title = "Public exposure (15-min checks)"
      type  = "line"
      width = 6
      sql   = <<-EOQ
        select scan_time, total::int as exposed_resources
        from csv.exposure_history order by scan_time
      EOQ
    }
  }

  # ---------------------------------------------------------------- Section B
  container {
    title = "B · Public exposure (live)"

    table {
      title = "Publicly accessible storage"
      width = 6
      sql   = <<-EOQ
        select name as bucket, bucket_policy_is_public as public_policy,
               block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets
        from aws_s3_bucket
        where bucket_policy_is_public
           or not (block_public_acls and ignore_public_acls and block_public_policy and restrict_public_buckets)
      EOQ
    }
    table {
      title = "Security groups exposing administrative ports"
      width = 6
      sql   = <<-EOQ
        select r.group_id, g.group_name, r.ip_protocol, r.from_port, r.to_port,
               coalesce(r.cidr_ipv4, r.cidr_ipv6) as source
        from aws_vpc_security_group_rule r
        join aws_vpc_security_group g on g.group_id = r.group_id
        where not r.is_egress
          and (r.cidr_ipv4 = '0.0.0.0/0' or r.cidr_ipv6 = '::/0')
          and (r.ip_protocol = '-1' or exists (
                select 1 from unnest(array[22, 3389, 3306, 5432, 2375, 2376]) p
                where r.from_port <= p and r.to_port >= p))
      EOQ
    }
    table {
      title = "Publicly accessible services (instance + public IP + open rule)"
      width = 6
      sql   = <<-EOQ
        select i.instance_id, i.tags ->> 'Name' as name, i.public_ip_address,
               sg ->> 'GroupName' as security_group, r.from_port, r.to_port,
               coalesce(i.tags ->> 'Exposure', '(undeclared)') as declared_exposure
        from aws_ec2_instance i
        cross join jsonb_array_elements(i.security_groups) sg
        join aws_vpc_security_group_rule r on r.group_id = sg ->> 'GroupId'
        where i.public_ip_address is not null and not r.is_egress and r.cidr_ipv4 = '0.0.0.0/0'
      EOQ
    }
    table {
      title = "Resources with incomplete access restrictions"
      width = 6
      sql   = <<-EOQ
        select 'instance' as kind, instance_id as resource,
               'IMDSv1 allowed (HttpTokens=' || (metadata_options ->> 'HttpTokens') || ')' as issue
        from aws_ec2_instance where metadata_options ->> 'HttpTokens' <> 'required'
        union all
        select 'security-group', group_id, 'default security group has rules'
        from aws_vpc_security_group
        where group_name = 'default'
          and (jsonb_array_length(coalesce(ip_permissions, '[]')) > 0
               or jsonb_array_length(coalesce(ip_permissions_egress, '[]')) > 0)
        union all
        select 'bucket', name, 'public access block incomplete'
        from aws_s3_bucket
        where not (block_public_acls and ignore_public_acls and block_public_policy and restrict_public_buckets)
      EOQ
    }
  }

  # ---------------------------------------------------------------- Section C
  container {
    title = "C · Compliance (latest Prowler assessment)"

    text {
      width = 12
      value = "**Pass rate** = PASS ÷ (PASS + FAIL) of checks mapped to the framework. MANUAL checks are excluded and listed separately. This is an internal metric, not the official benchmark score: the official per-control result is the Powerpipe benchmark `aws_compliance.benchmark.cis_v500` / `nist_800_53_rev_5`."
    }
    card {
      width = 3
      sql   = <<-EOQ
        select 'CIS pass rate %' as label,
               round(100.0 * count(*) filter (where status = 'PASS')
                     / nullif(count(*) filter (where status in ('PASS','FAIL')), 0), 1) as value
        from csv.prowler_findings where cis <> ''
      EOQ
    }
    card {
      width = 3
      sql   = <<-EOQ
        select 'NIST 800-53 r5 pass rate %' as label,
               round(100.0 * count(*) filter (where status = 'PASS')
                     / nullif(count(*) filter (where status in ('PASS','FAIL')), 0), 1) as value
        from csv.prowler_findings where nist_800_53 <> ''
      EOQ
    }
    card {
      width = 3
      sql   = <<-EOQ
        select 'Failed security controls (checks)' as label, count(distinct check_id) as value,
               case when count(*) > 0 then 'alert' else 'ok' end as type
        from csv.prowler_findings where status = 'FAIL'
      EOQ
    }
    card {
      width = 3
      sql   = <<-EOQ
        select 'Manual verification needed' as label, count(distinct check_id) as value, 'info' as type
        from csv.prowler_findings where status = 'MANUAL'
      EOQ
    }
    table {
      title = "Failed controls with CIS / NIST mapping"
      width = 12
      sql   = <<-EOQ
        select severity, check_id, check_title, count(*) as resources,
               max(cis) as cis_requirement, max(nist_800_53) as nist_800_53_controls
        from csv.prowler_findings
        where status = 'FAIL'
        group by severity, check_id, check_title
        order by case severity when 'Critical' then 1 when 'High' then 2
                               when 'Medium' then 3 when 'Low' then 4 else 5 end, resources desc
      EOQ
    }
    table {
      title = "Controls requiring manual verification"
      width = 12
      sql   = <<-EOQ
        select distinct check_id, check_title, max(cis) as cis_requirement
        from csv.prowler_findings where status = 'MANUAL'
        group by check_id, check_title
      EOQ
    }
  }

  # ---------------------------------------------------------------- Section D
  container {
    title = "D · Remediation tracking"

    card {
      width = 2
      sql   = "select 'Awaiting remediation' as label, count(*) as value, case when count(*) > 0 then 'alert' else 'ok' end as type from csv.findings_register where status = 'open'"
    }
    card {
      width = 2
      sql   = "select 'Being remediated' as label, count(*) as value, 'info' as type from csv.findings_register where status = 'in_progress'"
    }
    card {
      width = 2
      sql   = "select 'Resolved' as label, count(*) as value, 'ok' as type from csv.findings_register where status = 'resolved'"
    }
    card {
      width = 2
      sql   = "select 'Accepted (exception)' as label, count(*) as value, 'info' as type from csv.findings_register where status = 'accepted'"
    }
    card {
      width = 2
      sql   = "select 'Recurring violations' as label, count(*) as value, case when count(*) > 0 then 'alert' else 'ok' end as type from csv.findings_register where recurrence_count::int > 0"
    }
    card {
      width = 2
      sql   = <<-EOQ
        select 'Remediation rate %' as label,
               round(100.0 * count(*) filter (where status = 'resolved')
                     / nullif(count(*) filter (where status <> 'accepted'), 0), 1) as value
        from csv.findings_register
      EOQ
    }
    table {
      title = "Findings register"
      width = 12
      sql   = <<-EOQ
        select finding_id, severity, status, resource, requirement, owner,
               detected_at, resolved_at, recurrence_count, evidence
        from csv.findings_register
        order by case status when 'open' then 1 when 'in_progress' then 2
                             when 'accepted' then 3 else 4 end, finding_id
      EOQ
    }
  }

  # ---------------------------------------------------------------- Section E
  container {
    title = "E · Cloud inventory"

    chart {
      title = "Resources by service"
      type  = "bar"
      width = 4
      sql   = "select split_part(arn, ':', 3) as service, count(*) as resources from aws_tagging_resource group by 1 order by 2 desc"
    }
    chart {
      title = "Resources by region"
      type  = "donut"
      width = 4
      sql   = "select coalesce(nullif(region, ''), 'global') as region, count(*) from aws_tagging_resource group by 1"
    }
    chart {
      title = "Resources by environment"
      type  = "donut"
      width = 4
      sql   = "select coalesce(tags ->> 'Environment', 'UNTAGGED') as environment, count(*) from aws_tagging_resource group by 1"
    }
    table {
      title = "Resources without required tags (Project, Owner, Environment)"
      width = 12
      sql   = <<-EOQ
        select 'ec2' as service, instance_id as resource, region from aws_ec2_instance
          where tags ->> 'Owner' is null or tags ->> 'Project' is null or tags ->> 'Environment' is null
        union all
        select 's3', name, region from aws_s3_bucket
          where tags ->> 'Owner' is null or tags ->> 'Project' is null or tags ->> 'Environment' is null
        union all
        select 'security-group', group_id, region from aws_vpc_security_group
          where tags ->> 'Owner' is null or tags ->> 'Project' is null or tags ->> 'Environment' is null
        union all
        select 'vpc', vpc_id, region from aws_vpc
          where tags ->> 'Owner' is null or tags ->> 'Project' is null or tags ->> 'Environment' is null
        union all
        select 'ebs', volume_id, region from aws_ebs_volume
          where tags ->> 'Owner' is null or tags ->> 'Project' is null or tags ->> 'Environment' is null
      EOQ
    }
  }
}

query "public_exposure_count" {
  sql = <<-EOQ
    with exposed as (
      select arn as id from aws_s3_bucket
       where bucket_policy_is_public
          or not (block_public_acls and ignore_public_acls and block_public_policy and restrict_public_buckets)
      union
      select r.group_id from aws_vpc_security_group_rule r
       where not r.is_egress and (r.cidr_ipv4 = '0.0.0.0/0' or r.cidr_ipv6 = '::/0')
         and (r.ip_protocol = '-1' or exists (
               select 1 from unnest(array[22, 3389, 3306, 5432, 2375, 2376]) p
               where r.from_port <= p and r.to_port >= p))
      union
      select instance_id from aws_ec2_instance
       where public_ip_address is not null and tags ->> 'Exposure' is null
    )
    select 'Unintended public exposure' as label, count(*) as value,
           case when count(*) > 0 then 'alert' else 'ok' end as type
    from exposed
  EOQ
}
