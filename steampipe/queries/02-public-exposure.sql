-- Milestone 4 / Step 6 - public storage and network exposure

-- Buckets whose bucket POLICY is public (real exposure)
select name, region, account_id, bucket_policy_is_public
from aws_s3_bucket where bucket_policy_is_public = true;

-- Buckets without ALL four public access block settings (missing guard rail)
select name, region, block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets
from aws_s3_bucket
where block_public_acls = false or block_public_policy = false
   or ignore_public_acls = false or restrict_public_buckets = false;

-- Security-group rules opening administrative ports to the internet
select r.group_id, g.group_name, r.ip_protocol, r.from_port, r.to_port, r.cidr_ipv4, r.cidr_ipv6
from aws_vpc_security_group_rule r
join aws_vpc_security_group g on g.group_id = r.group_id
where not r.is_egress
  and (r.cidr_ipv4 = '0.0.0.0/0' or r.cidr_ipv6 = '::/0')
  and (r.ip_protocol = '-1' or exists (
        select 1 from unnest(array[22, 3389, 3306, 5432, 2375, 2376]) p
        where r.from_port <= p and r.to_port >= p));
