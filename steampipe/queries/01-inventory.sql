-- Milestone 4 / Step 5 - cloud resource inventory
-- Run one statement at a time in `steampipe query`, or: steampipe query 01-inventory.sql

-- S3 buckets
select name, region, account_id from aws_s3_bucket;

-- EC2 instances
select instance_id, instance_type, instance_state, public_ip_address, region from aws_ec2_instance;

-- Security groups
select group_id, group_name, description, vpc_id from aws_vpc_security_group;

-- Everything that carries tags, grouped by service (uses the tagging API)
select split_part(arn, ':', 3) as service, count(*) as resources
from aws_tagging_resource group by 1 order by 2 desc;

-- Resources by environment tag
select coalesce(tags ->> 'Environment', 'UNTAGGED') as environment, count(*)
from aws_tagging_resource group by 1;
