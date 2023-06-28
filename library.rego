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


package sarif

import future.keywords.if
import future.keywords.in

default format := false



filtered_runs (ids, levels, precisions, ignore) = { id |
   format;
   rule = data.runs[0].tool.driver.rules[_]
   id_check(rule.id, ids)
   # rule.id in input.ruleIDs
   level_check(rule.defaultConfiguration.level, levels)
   # rule.defaultConfiguration.level in input.ruleLevel;
   precision_check(rule.properties.precision, precisions)
   # rule.properties.precision in input.precision;
   ignore_check(rule.id, ignore)
   # not (rule.id in input.ignore);
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
   input.ruleLevel
   input.precision
   input.location
   input.ruleIDs
   input.ignore
}

filter_list (ids, levels, precisions, ignore) = { summary |
   result = data.runs[0].results[_]
   lst := filtered_runs(ids, levels, precisions, ignore)
   result.ruleId in lst
   summary = {
      "------------------": "------------------",
      "ruleID": result.ruleId,
      "file": result.locations[0].physicalLocation.artifactLocation.uri,
      "region": result.locations[0].physicalLocation.region,
      "message": result.message.text,
   }
} if { count(filtered_runs(ids, levels, precisions, ignore)) > 0 } else := "no problems found!"

# Library of a few rego functions that can be used for SARIF analysis.


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
