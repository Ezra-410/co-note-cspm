-- Investigation: JOIN resources together (question 8 - correlation with SQL)

-- Which INSTANCES are reachable from the internet, and through WHICH rule?
-- (an instance is only exposed if it has a public IP AND an attached group
--  allows inbound traffic from 0.0.0.0/0)
select i.instance_id, i.tags ->> 'Name' as name, i.public_ip_address,
       sg ->> 'GroupId' as group_id, r.ip_protocol, r.from_port, r.to_port
from aws_ec2_instance i
cross join jsonb_array_elements(i.security_groups) sg
join aws_vpc_security_group_rule r on r.group_id = sg ->> 'GroupId'
where i.public_ip_address is not null
  and not r.is_egress
  and r.cidr_ipv4 = '0.0.0.0/0'
order by i.instance_id, r.from_port;

-- IAM users: MFA and console access (identity hygiene)
select name, mfa_enabled, password_last_used, create_date from aws_iam_user;

-- Resources missing a required tag (governance / ownership)
select 'ec2' as service, instance_id as id from aws_ec2_instance
  where tags ->> 'Owner' is null or tags ->> 'Project' is null
union all
select 's3', name from aws_s3_bucket
  where tags ->> 'Owner' is null or tags ->> 'Project' is null
union all
select 'security-group', group_id from aws_vpc_security_group
  where tags ->> 'Owner' is null or tags ->> 'Project' is null;
