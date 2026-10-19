package terraform.security

import rego.v1

# Deny EC2 instances with an unencrypted root EBS volume
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_instance"
	some action in rc.change.actions
	action in {"create", "update"}

	after := rc.change.after
	after_unknown := object.get(rc.change, "after_unknown", {})

	root_devices := object.get(after, "root_block_device", [])
	some idx, block in root_devices

	not is_encrypted(block, root_unknown_block(after_unknown, idx))

	msg := sprintf(
		"EC2 instance '%s' has an unencrypted or unverified root EBS volume",
		[rc.address],
	)
}

# Deny EC2 instances with unencrypted additional EBS block devices
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_instance"
	some action in rc.change.actions
	action in {"create", "update"}

	after := rc.change.after
	after_unknown := object.get(rc.change, "after_unknown", {})

	ebs_devices := object.get(after, "ebs_block_device", [])
	some idx, block in ebs_devices

	not is_encrypted(block, ebs_unknown_block(after_unknown, idx))

	msg := sprintf(
		"EC2 instance '%s' has an unencrypted or unverified additional EBS volume at index %d",
		[rc.address, idx],
	)
}

# Deny standalone aws_ebs_volume resources that are unencrypted
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_ebs_volume"
	some action in rc.change.actions
	action in {"create", "update"}

	after := rc.change.after
	after_unknown := object.get(rc.change, "after_unknown", {})

	not is_encrypted(after, after_unknown)

	msg := sprintf(
		"EBS volume '%s' is unencrypted or has an unverified encryption setting",
		[rc.address],
	)
}

# Helper: determine if a block (object with 'encrypted' attribute) is confirmed encrypted
is_encrypted(block, unknown) if {
	block.encrypted == true
	not unknown_encrypted(unknown)
}

unknown_encrypted(unknown) if {
	unknown.encrypted == true
}

unknown_encrypted(unknown) if {
	is_boolean(unknown)
	unknown == true
}

# Helper: extract the 'after_unknown' entry for root_block_device at given index
root_unknown_block(after_unknown, idx) := result if {
	devices := object.get(after_unknown, "root_block_device", [])
	count(devices) > idx
	result := devices[idx]
} else := {}

# Helper: extract the 'after_unknown' entry for ebs_block_device at given index
ebs_unknown_block(after_unknown, idx) := result if {
	devices := object.get(after_unknown, "ebs_block_device", [])
	count(devices) > idx
	result := devices[idx]
} else := {}
