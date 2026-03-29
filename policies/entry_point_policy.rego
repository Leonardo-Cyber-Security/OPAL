# Entry Policy - Policy sfruttata dall'API Gateway per autorizzare le richieste in ingresso
package httpapi.authz

import data.httpapi.authz.utils
import data.httpapi.authz.apis
import data.httpapi.authz.pages

default decision := {"allow": false, "column_mask": {}, "row_filter": {}}

decision := {"allow": true, "column_mask": apis.column_mask, "row_filter": apis.row_filter} if {
	print("Check Access Granted with API policy")
  	apis.allow
  	print("Access granted to API:", input.method, "-", input.path)
}

decision := {"allow": true, "column_mask": {}, "row_filter": {}} if {
  	not apis.allow
  	print("Check Access Granted with Page policy")
  	pages.allow
  	print("Access granted to Page:", input.path)
}
