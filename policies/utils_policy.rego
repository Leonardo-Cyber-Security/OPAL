package httpapi.authz.utils

path_match(data_path, input_path) if {
    safe_pattern := replace(data_path, "**", ".*")
    regex_pattern := sprintf("^(%s)$", [safe_pattern])
    regex.match(regex_pattern, input_path)
    print("Input path", input_path, " matched with:", data_path)
}

method_match(data_method, input_method) if (data_method == input_method)
else if (data_method == "*")
else if (data_method == "ALL")