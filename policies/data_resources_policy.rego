package httpapi.authz.datas

import data.httpapi.authz.jwt
import data.datas as data_datas

compute_masked_fields(data_api) = column_mask if {
    column_mask := {action: masked_fields |
        some data_data in data_datas
        regex.match(data_api.urn, data_data.urn)
        jwt.allow(data_data)
        action = data_data.action
		not data_data.filter
        masked_fields = {field: "****" | some field in data_data.fields}
        print("Masked fields in:", action, masked_fields)
    }
}

compute_row_filter(data_api) = row_filter if {
    row_filter := {action: filter |
        some data_data in data_datas
        regex.match(data_api.urn, data_data.urn)
        data_data.filter
        jwt.filter_group_allow(data_data)
        action := data_data.action
        matched_groups := jwt.filter_groups(data_data)
        filter := {
            "type": "array_any_prefix",
            "field": "groups",
            "values": matched_groups
        }
    }
}
