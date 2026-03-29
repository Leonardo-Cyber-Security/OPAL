package httpapi.authz.pages

import data.httpapi.authz.utils
import data.httpapi.authz.jwt
import data.pages as data_pages

default allow := false

page_matches(data_page) if {
	data_page.route == input.path
} else if {
    utils.path_match(data_page.route, input.path)
}

allow if {
	some data_page in data_pages
  	page_matches(data_page)
  	jwt.allow(data_page)
  	print("PAGE", data_page.route, "granted!")
}