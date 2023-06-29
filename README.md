# Rego Functions for SARIF

rego code for verifying policies on SARIF and related formats (generic attestations such as SAST, DAST etc.)

data.json and input.json are examples of SAST output files formatted as SARIF (for input to program) and criteria/filter input, respectively

---
### How to Evaluate Each Policy

Make sure you have `opa` installed in your path

Put the `library.rego` and `input.json` file into the same directory that your SAST output file is in

Run `opa eval -i input.json -d <output_file>.json -d library.rego "data.sarif.<policy_name>"`

- Put your input criteria into a JSON formatted file as such:

```
   {
      "ruleLevel": [],
      "precision": [],
      "ruleIDs": [],
      "ignore": []
   }
```

- The `input.json` file is a filter that will be placed on the sarif
   - make sure it is in the same directory as `library.rego`
   - if any category is left empty, it will not be considered
   - `ruleLevel` should contain 0+ strings of a sarif finding level
      - for example, if the value is `["warning", "error"]`, the filter will only include rules of level "warning" and "error".
   - `precision` should contain 0+ strings of a sarif precision level
      - example: `["high", "very-high"]` for findings that are only of those precision levels
   - `ruleIDs` should contain 0+ strings of rule ids
      - example: `["abcd123"]` for findings only triggered by rule "abcd132"
   - `ignore` should contain 0+ strings of rule ids to be ignored
      - if it is empty, zero rules will be ignored during evaluation
      - if it is "all", every rule will be ignored during evaluation
- Take a SAST output file in a SARIF format, as a JSON
   - make sure it matches up with the title of `<output_file>` and is a .json extension
   - put it in the same directory as `library.rego` and `input.json`
- It can be formatted however the user pleases (through  the  `--format=` flag), although `pretty` will be the most comprehensible
- `<policy_name>` is the name of the policy as specified below
   - example: to run `pass_no_filters`, run `opa eval -i input.json -d <output_file>.json -d library.rego --format=pretty "data.sarif.pass_no_filters"`
   - another example: to run `status_count(level)` with a level of `very-high`, run `opa eval -i input.json -d <output_file>.json -d library.rego --format=pretty "data.sarif.status_count("very_high")"`

---

### Overview of Policies

#### `pass_no_filters`

- Type: `boolean`
- Determines whether or not the program scanned by the SAST tool passes
   - i.e. there were zero findings according every rule used by the tool

#### `pass`

- Type: `boolean`
- Determines, according to the rule filters, whether or not the program scanned by the SAST tool passes
   - i.e. there were zero findings according to the rules filtered by the input criteria

#### `pass_by_threshold(n, use_filters)`

- Type: `boolean`
- Determines whether or not there were `n` or less findings, and passes if so
   - if `use_filters` is true, it will only use findings complying with the filters
   - if `use_filters` is false it will include all findings in its determination of a pass

#### `rule_count`

- Type: `int`
- Returns the total number of rules used for scanning present in the sarif file
   - for example: `rule_count == 4` if there were 4 rules used for scanning

#### `rules_evaluated_count`

- Type `int`
- Returns the total number of findings according to the sarif file
   - for example: `rules_evaluated_count == 16` if there were 16 total findings reported by the SAST tool

#### `rule_list`

- Type: `array`
- Returns an array of JSON objects where each has the id of a rule, and a description of it
   - for example: an entry in that array could look like:

   ```
   {
      "description": "You probably want the structural equality operator =",
      "id": "ocaml.lang.correctness.physical-vs-structural.physical-equal"
   }
   ```

#### `status_count(level)`

- Type: `int`
- Returns the number of results in the filtered list of findings with the finding level `level`
   - for example: `status_count("very-high")` returns the number of findings with the level `"very-high"`

#### `filter_count`

- Type: `int`
- Returns the number of rules complying to the input criteria

#### `synopsis`

- Type: `array`
- Returns a synopsis of the findings, after the filter is applied
- Each entry is a JSON object as such:

```
        {
          "------------------": "------------------",
          "file": "_build/default/src/lexer.ml",
          "message": "You probably want the structural equality operator =",
          "region": {
            "endColumn": 54,
            "endLine": 60,
            "snippet": {
              "text": "| h :: t -> if odd qc then (h :: help t (if h == '\\\"' then qc + 1 else qc))  else (if (whitespace h) then (help t qc) else (h :: help t (if h == '\\\"' then qc + 1 else qc)))"
            },
            "startColumn": 45,
            "startLine": 60
          },
          "ruleID": "ocaml.lang.correctness.physical-vs-structural.physical-equal"
        },
```

#### `results_by_rule_id (rule_id)`

- Type: `array`
- Creates a synopsis using only findings triggered by rules in the `rule_id` array
- `rule_id` should be an array containing rule ids as such: `["ocaml.lang.correctness.physical-vs-structural.physical-equal"]`
