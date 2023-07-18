# IMPORTANT DETAILS:
# Use the 'input.json' file to specify the filters to be placed on the sarif
# file for the creation of a synopsis. If you leave a certain field empty,
# the policies will not place any filters on that field. Otherwise, only rules
# that match that filter will be included in the synposis.
#
# Make sure that your sarif file to be scanned is in the same directory as this
# file and that it is named 'data.json'
#
# If, for whatever reason, you want to ignore every rule, replace the "ignore"
# value array with the string "all" and every rule will be ignored.
#
# The 'filtered_runs' array in the output will show you the list of rules that
# were considered in the synopsis
#
# A line of "------------" marks the start of a new finding summary

# The config JSON object defined in the beginning of this file is synonymous to
# the JSON object found in input.json. Initially, that was used at the input
# criteria for these functions. Now, we use the config JSON object defined in
# in this library.


package sarif

import future.keywords.if
import future.keywords.in

default format := false
default pass_no_filters(of) := false
default pass(of) := false
# default pass_by_threshold(n, use_filters) := false

# User must pass in either a pointer to the JSON data or the data itself
# (of the SAST tool output file)

config := {
   "ruleLevel": ["note"],
   "precision": [],
   "ruleIDs": [],
   "ignore": [],
   "maxAllowed": 10
}

get_rules(output_file) = rules {
   rules := output_file.runs[0].tool.driver.rules
}

get_results(output_file) = results {
   results := output_file.runs[0].results
}

filtered_runs(ids, levels, precisions, ignore, of) = { id |
   format;
   rules = get_rules(of)
   rule = rules[_]
   id_check(rule.id, ids)
   # rule.id in config.ruleIDs
   level_check(rule.defaultConfiguration.level, levels)
   # rule.defaultConfiguration.level in config.ruleLevel;
   precision_check(rule.properties.precision, precisions)
   # rule.properties.precision in config.precision;
   ignore_check(rule.id, ignore)
   # not (rule.id in config.ignore);
   id = rule.id
} if { not (ignore == "all") } else := []

level_check (level, filters) {
   count(filters) == 0
}

level_check (level, filters) {
   level in filters
}

precision_check (precision, filters) {
   count(filters) == 0
}

precision_check (precision, filters) {
   precision in filters
}

id_check (id, filters) {
   count(filters) == 0
}

id_check (id, filters) {
   id in filters
}

ignore_check (ignore, filters) {
   count(filters) == 0
}

ignore_check (ignore, filters) {
   not (ignore in filters)
}

format {
   config.ruleLevel
   config.precision
   config.ruleIDs
   config.ignore
}

filter_list (ids, levels, precisions, ignore, of) = { summary |
   result = of.runs[0].results[_]
   lst := filtered_runs(ids, levels, precisions, ignore, of)
   result.ruleId in lst
   summary = {
      "------------------": "------------------",
      "ruleID": result.ruleId,
      "file": result.locations[0].physicalLocation.artifactLocation.uri,
      "region": result.locations[0].physicalLocation.region,
      "message": result.message.text,
   }
} if { count(filtered_runs(ids, levels, precisions, ignore, of)) > 0 } else := "no problems found!"

# Library of a few rego functions that can be used for SARIF analysis.

# returns the total number of rules used for evaluation in the sarif
rule_count(of) = n {
   n := count(get_rules(of))
}

# returns the total evaluations returned by the tool reported in the sarif
rules_evaluated_count(of) = n {
   n := count(get_results(of))
}

# returns a quick summary of each rule used for evaluation in the sarif
rule_list(of) = { rule_summary |
   rule_entry := of.runs[0].tool.driver.rules[_];
   rule_summary := {
      "id": rule_entry.id,
      "description": rule_entry.fullDescription.text,
      "level": rule_entry.defaultConfiguration.level
   }
}

# returns the number of results returned by SAST tool that have the status
# specified in the parameter
status_count (level, of) = n {
   arr = filter_list([], [level], [], [], of)
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

# returns a count of the rules after applying the config filters/criteria
filter_count(of) = n {
   n := count(filtered_runs(config.ruleIDs, config.ruleLevel, config.precision, config.ignore, of))
}

# returns the filtered list of results from the sarif file
synopsis(of)= res {
   res := filter_list(config.ruleIDs, config.ruleLevel, config.precision, config.ignore, of)
}

# creates a synopsis using only rules specified in the array parameter
results_by_rule_id(rule_id, of) = result {
   result := filter_list(rule_id, [], [], [], of)
}

# determines whether the SAST results pass with no user-specified filters
pass_no_filters(of) {
   filter_list([], [], [], [], of) == "no problems found!"
}

# determines whether the SAST results pass using the 'input.json' specified filters
pass(of) = true {
   synopsis(of) == "no problems found!"
} else = (count(synopsis(of)) <= config.maxAllowed)


# summarizes findings
# summary(of) = res {
#    res := {
#       "allow": pass(of),
#       "count": filter_count(of)
#    }
# }

# pass_by_threshold_help(use_filters) := n {
#    use_filters == true
#    n := synopsis
# }

# pass_by_threshold_help(use_filters) := n {
#    use_filters == false
#    n := filter_list([], [], [], [])
# }


# default pass_by_threshold(_, _) = false

# pass_by_threshold_more_help(n, use_filters) = ret {
#    pass_by_threshold_help(use_filters) == "no problems found!"
#    ret := 0
# }

# pass_by_threshold_more_help(n, use_filters) = ret {
#    res := pass_by_threshold_help(use_filters)
#    res != "no problems found!"
#    ret := count(res)
# }

# pass_by_threshold(n, use_filters) {
#    pass_by_threshold_more_help(n, use_filters) <= n
# }

