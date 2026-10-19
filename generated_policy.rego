package terraform.security

import rego.v1

# -----------------------------------------------------------------------------
# Helper: determine if the resource change action set includes create or update
# -----------------------------------------------------------------------------
is_relevant_action(actions) if {
	some a in actions
	a == "create"
}

is_relevant_action(actions) if {
	some a in actions
	a == "update"
}

# -----------------------------------------------------------------------------
# Helper: detect public IPv4 exposure via associate_public_ip_address
# -----------------------------------------------------------------------------
has_public_ipv4(rc) if {
	rc.change.after.associate_public_ip_address == true
}

has_public_ipv4(rc) if {
	rc.change.after_unknown.associate_public_ip_address == true
}

# -----------------------------------------------------------------------------
# Helper: detect public IPv4 exposure via network_interface blocks
# -----------------------------------------------------------------------------
has_public_ipv4(rc) if {
	some ni in rc.change.after.network_interface
	ni.associate_public_ip_address == true
}

has_public_ipv4(rc) if {
	some ni in rc.change.after_unknown.network_interface
	ni.associate_public_ip_address == true
}

# -----------------------------------------------------------------------------
# Helper: detect IPv6 exposure via ipv6_address_count or ipv6_addresses
# -----------------------------------------------------------------------------
has_public_ipv6(rc) if {
	rc.change.after.ipv6_address_count > 0
}

has_public_ipv6(rc) if {
	count(rc.change.after.ipv6_addresses) > 0
}

has_public_ipv6(rc) if {
	rc.change.after_unknown.ipv6_address_count == true
}

has_public_ipv6(rc) if {
	rc.change.after_unknown.ipv6_addresses == true
}

# -----------------------------------------------------------------------------
# Deny: EC2 instances configured with a public IPv4 address
# -----------------------------------------------------------------------------
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_instance"
	is_relevant_action(rc.change.actions)
	has_public_ipv4(rc)
	msg := sprintf(
		"EC2 instance %q is configured (or planned) with a public IPv4 address. Review 'associate_public_ip_address' or 'network_interface' settings.",
		[rc.address],
	)
}

# -----------------------------------------------------------------------------
# Deny: EC2 instances configured with a public IPv6 address
# -----------------------------------------------------------------------------
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_instance"
	is_relevant_action(rc.change.actions)
	has_public_ipv6(rc)
	msg := sprintf(
		"EC2 instance %q is configured (or planned) with a public IPv6 address. Review 'ipv6_address_count' or 'ipv6_addresses' settings.",
		[rc.address],
	)
}
