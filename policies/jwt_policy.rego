# JWT Policy - Policy sfruttata per controllare i claim del JWT

package httpapi.authz.jwt

same_or_ancestor(allowed_group, user_group) if {
	print("Check same group")
    same_group(allowed_group, user_group)
    print("Granted by group same name")
} else if {
	print("Check group hierarchy")
	startswith(allowed_group, sprintf("%s/", [user_group]))
	print("Granted: Is ancestor")
}

same_group(allowed_group, user_group) if {
	print("Check group eq name")
	user_group == allowed_group
	print("Granted: Names are equals")
} else if {
	print("Check group eq paths")
	user_group == concat("", ["/", allowed_group])
	print("Granted: Paths are equals")
}

filter_groups(data_obj) = matched_groups if {
    matched_groups := [user_group |
        some allowed_group in data_obj.groups
        some user_group in input.token.payload.groups
        same_group(allowed_group, user_group)
    ]
    count(matched_groups) > 0
}

is_allowed_user(data_obj) if {
    some allowed_username in data_obj.users
    input.token.payload.preferred_username == allowed_username
    print("Access granted from User:", allowed_username)
}

has_allowed_group(data_obj) if {
    some allowed_group in data_obj.groups
    some user_group in input.token.payload.groups
    same_or_ancestor(allowed_group, user_group)
    print("Access granted from Group:", allowed_group)
}

has_allowed_role(data_obj) if {
    some allowed_role in data_obj.roles
    some user_role in input.token.payload.iam_roles
    user_role == allowed_role
    print("Access granted from Role:", allowed_role)
}

allow(data_obj) if {
    has_allowed_role(data_obj)
} else if {
	has_allowed_group(data_obj)
} else if {
    is_allowed_user(data_obj)
}

filter_group_allow(data_obj) if {
    some allowed_group in data_obj.groups
    some user_group in input.token.payload.groups
    same_group(allowed_group, user_group)
}