-- Milestone 4 / Steps 7-8 - encryption and versioning

-- Buckets without default encryption
select name, region, server_side_encryption_configuration
from aws_s3_bucket where server_side_encryption_configuration is null;

-- Buckets without versioning
select name, region, versioning_enabled from aws_s3_bucket where versioning_enabled = false;

-- Unencrypted EBS volumes
select volume_id, state, encrypted, region from aws_ebs_volume where not encrypted;
