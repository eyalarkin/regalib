# Library of a few rego functions that can be used for SARIF analysis.

package sarif

default pass_no_filters := false
default pass := false

# returns the total number of rules used for evaluation in the sarif
rule_count = n {
   n := count(data.runs[0].tool.driver.rules)
}

# returns the total evaluations returned by the tool reported in the sarif
rules_evaluated_count = n {
   n := count(data.runs[0].results)
}

# returns a quick summary of each rule used for evaluation in the sarif
rule_list = { rule_summary |
   rule_entry := data.runs[0].tool.driver.rules[_];
   rule_summary := {
      "id": rule_entry.id,
      "description": rule_entry.fullDescription.text
   }
}

# returns the number of results returned by SAST tool that have the status
# specified in the parameter
status_count (status) = n {
   arr = filter_list([], [status], [], [])
   n := status_count_helper(arr)
}

# helper function: if synposis is an array, return count of array
status_count_helper (arr) = n {
   arr != "no problems found!"
   n := count(arr)
}

# helper function: if synposis is "no problems found!", return 0
status_count_helper (arr) = n {
   arr == "no problems found!"
   n := 0
}

# num_warn := status_count("warning")

# returns a count of the rules after applying the input filters/criteria
filter_count = n {
   n := count(filtered_runs(input.ruleIDs, input.ruleLevel, input.precision, input.ignore))
}

# returns the filtered list of results from the sarif file
synopsis = res {
   res := filter_list(input.ruleIDs, input.ruleLevel, input.precision, input.ignore)
}

# creates a synopsis using only rules specified in the array parameter
results_by_rule_id (rule_id) = result {
   result := filter_list(rule_id, [], [], [])
}

# determines whether the SAST results pass with no user-specified filters
pass_no_filters {
   filter_list([], [], [], []) == "no problems found!"
}

# determines whether the SAST results pass using the 'input.json' specified filters
pass {
   synopsis == "no problems found!"
}
