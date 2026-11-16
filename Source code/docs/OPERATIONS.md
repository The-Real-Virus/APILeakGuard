# App operation access

| Operation | Desktop | CLI | Assistant | Required inputs and approval | Acceptance |
| --- | --- | --- | --- | --- | --- |
| Manage projects and scopes | Projects and suites | project | — | Approve the project origin and base path per API and environment | F01 F02 |
| Run fixed functional suite | Automated tests | preview, approve, run | Review the current plan | Review exact request plan. Authorize state-changing operations explicitly. The assistant can open the current plan for review. The user starts network activity in the request workflow. | F01 F08 R02 |
| Analyze local evidence | Imported evidence | inspect, analyze | Analyze selected evidence | Select local files and verify mapping. Assistant receives a typed action with no path parameters. | F03 F09 R02 |
| Review inventory and coverage | Results and evidence | inventory, coverage | Coverage or Inventory | Select a saved local run | F03 F06 F08 R02 |
| Inspect evidence | Pretty, Raw and local reveal | report, search | Masked summary | Reveal requires the exact source file and approval | F09 F10 |
| Compare with a policy | Policy comparison | policy-validate, policy-compare | Compare selected policy | Select an existing run and a local policy. Validate its structured rules. | F05 F11 R02 |
| Export masked report | Export report | report --out | Export masked report | Select target. Replacing an export needs confirmation. Assistant exports to a new selected file. | F06 F11 R02 |
| Plan and track remediation | Remediation and Track finding | remediation, review, compare | Read remediation plan | Select run and relevant finding | F07 F11 R02 |
| Preview and apply a fix | Remediation | fix | Draft selected fix | Select local file and field path. Apply after the exact preview is approved. | F07 F11 R02 |
| Cancel job | Cancel job | Ctrl+C | Shared job cancellation | Cancel the app's active job | F01 R03 |

The app runs fixed functional operations. Discovered destinations begin as pending inventory items and are inert until included in a separately approved plan.
