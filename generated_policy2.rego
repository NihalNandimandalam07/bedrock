package terraform.security

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	some action in resource.change.actions
	action in ["create", "update"]

	values := resource.change.after

	is_block_disabled(values)

	msg := sprintf(
		"S3 bucket public access block '%s' does not fully restrict public access (block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets must all be true).",
		[resource.address],
	)
}

is_block_disabled(values) if {
	not values.block_public_acls == true
}

is_block_disabled(values) if {
	not values.block_public_policy == true
}

is_block_disabled(values) if {
	not values.ignore_public_acls == true
}

is_block_disabled(values) if {
	not values.restrict_public_buckets == true
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_acl"
	some action in resource.change.actions
	action in ["create", "update"]

	values := resource.change.after

	values.acl in ["public-read", "public-read-write", "authenticated-read"]

	msg := sprintf(
		"S3 bucket ACL '%s' grants public access via ACL '%s'.",
		[resource.address, values.acl],
	)
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_policy"
	some action in resource.change.actions
	action in ["create", "update"]

	values := resource.change.after

	policy_allows_public_access(values.policy)

	msg := sprintf(
		"S3 bucket policy '%s' allows public access (Principal '*' without restrictive conditions).",
		[resource.address],
	)
}

policy_allows_public_access(policy) if {
	is_string(policy)
	decoded := json.unmarshal(policy)
	some statement in decoded.Statement
	statement.Effect == "Allow"
	principal_is_wildcard(statement.Principal)
}

principal_is_wildcard(principal) if {
	principal == "*"
}

principal_is_wildcard(principal) if {
	principal.AWS == "*"
}

principal_is_wildcard(principal) if {
	some aws_principal in principal.AWS
	aws_principal == "*"
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	some action in resource.change.actions
	action in ["create", "update"]

	values := resource.change.after

	values.acl in ["public-read", "public-read-write", "authenticated-read"]

	msg := sprintf(
		"S3 bucket '%s' grants public access via deprecated inline ACL '%s'.",
		[resource.address, values.acl],
	)
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	some action in resource.change.actions
	action in ["create", "update"]

	values := resource.change.after

	some grant in values.grant

	grant_is_public(grant)

	msg := sprintf(
		"S3 bucket '%s' has a grant allowing public access via URI '%s'.",
		[resource.address, grant.uri],
	)
}

grant_is_public(grant) if {
	grant.uri == "http://acs.amazonaws.com/groups/global/AllUsers"
}

grant_is_public(grant) if {
	grant.uri == "http://acs.amazonaws.com/groups/global/AllUsers/"
}
