package httpapi.authz.apis

import data.httpapi.authz.utils
import data.httpapi.authz.jwt
import data.httpapi.authz.datas
import data.apis as data_apis

default allow := false
default column_mask := {}

api_matches(data_api) if {
	data_api.endpoint == input.path
	utils.method_match(data_api.method, input.method)
} else if {
    utils.path_match(data_api.endpoint, input.path)
	utils.method_match(data_api.method, input.method)
}

allow if {
	some data_api in data_apis
  	api_matches(data_api)
  	jwt.allow(data_api)
  	print("API", data_api.endpoint, "granted!")    
}

column_mask = mask if {
	some data_api in data_apis
  	api_matches(data_api)
  	jwt.allow(data_api)
  	mask := datas.compute_masked_fields(data_api)
  	print("Masked fields:", mask)
}

row_filter = row_filter if {
	some data_api in data_apis
  	api_matches(data_api)
  	jwt.allow(data_api)
  	row_filter := datas.compute_row_filter(data_api)
	print("Filter hierarchy by:", row_filter)
}