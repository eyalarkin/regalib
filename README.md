# Rego Functions for SARIF

rego code for verifying policies on SARIF and related formats (generic attestations such as SAST, DAST etc.)

data.json and input.json are examples of SAST output files formatted as SARIF (for input to program) and criteria/filter input, respectively

---
### How to Evaluate Each Policy

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
   - if the `ignore` value is "all", every single finding will be ignored
   - `ruleLevel` should contain 0+ strings of a sarif finding level
      - for example, if the value is `["warning", "error"]`, the filter will only include rules of level "warning" and "error".
   - `precision` should contain 0+ strings of a sarif precision level
      - example: `["high", "very-high"]` for findings that are only of those precision levels
   - `ruleIDs` should contain 0+ strings of rule ids
      - example: `["abcd123"]` for findings only triggered by rule "abcd132"
- Take a SAST output file in a SARIF format, as a JSON
   - make sure it matches up with the title of `<output_file>` and is a .json extension
   - put it in the same directory as `library.rego` and `input.json`
- It can be formatted however the user pleases (through  the  `--format=` flag), although some policies output better results with certain formats (will be specified)
- `<policy_name>` is the name of the policy as specified below
   - example: to run `pass_no_filters`, run `opa eval -i input.json -d <output_file>.json -d library.rego --format=pretty "data.sarif.pass_no_filters"`

---

### Overview of Policies

#### `pass_no_filters`

- Type: `boolean`
- Determines whether or not the program scanned by the SAST tool "passes"
   - i.e. there were zero findings according every rule used by the tool

#### `pass`

- Type: `boolean`
- Determines, according to the rule filters, whether or not the program scanned by the SAST tool "passes"
   - i.e. there were zero findings according to the rules filtered by the input criteria

#### `rule_count`
- Type: `int`
- Returns the total number of rules used for scanning present in the sarif file
   - for example: `rule_count == 4` if there were 4 rules used for scanning

#### `rules_evaluated_count`
- Type `int`
- Returns the total number of findings according to the sarif file
   - for example: `rules_evaluated_count == 16` if there were 16 total findings reported by the SAST tool

#### `rule_list`
- Type: `Array`
- Returns an array of JSON objects where each has the id of a rule, and a description of it
   - for example: an entry in that array could look like:

   ```
   {
      "description": "You probably want the structural equality operator =",
      "id": "ocaml.lang.correctness.physical-vs-structural.physical-equal"
   }
   ```
