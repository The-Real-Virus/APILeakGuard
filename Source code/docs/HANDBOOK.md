# APILeakGuard v1.0 user handbook

APILeakGuard sends a request to the endpoint you choose, shows the HTTP status and masked response, and flags fields or headers that may expose sensitive data. You can repeat the same requests as a suite or analyze responses you already saved. On **Overview**, choose **Run practice request** to send a GET to a demo API running briefly on your computer. It returns HTTP 200 and a fictional customer email. Open the finding, then choose **Open source** to inspect the evidence behind it.

## Set up on Windows

The x64 Windows package bundles its Python and Qt dependencies. Verify the SHA-256 checksums before extracting it. The package is unsigned. Extract the ZIP to a writable directory and double-click `APILeakGuard.exe` inside it. Open a console in that directory to run `apileakguard-cli.exe --help`.

In portable mode, extract the entire ZIP and launch the EXE beside the `portable.profile` marker and shared `_internal` folder. The profile is saved beside the executables. Both accept `--workspace` before a CLI subcommand or when launching the desktop. Preserve the portable profile when moving to a newer extracted build. Review the [Windows matrix and verification statuses](REMAINING-TESTS.md).

## Run an approved functional test

1. In **Manual request**, enter the full endpoint URL such as `https://api.example.com/orders/123`. Select the method from your API docs or Postman. When copying from another tool, use the resolved URL with variables such as the order ID filled in.
2. Under **Authentication**, choose **No authentication**, **Bearer token**, or **Saved credential profile**. Paste your existing access token into **Token** for the current plan. Remote authenticated APIs need HTTPS. For a reusable role, save a profile in **Settings**, enter its name, and match the API and environment under **Show advanced request settings**.
3. Choose **Preview request**. Review the method, URL, and authentication. Choose **Approve and run**, then **Allow**. The status appears at the top of **Results and evidence**. Use **Evidence** to view the masked response and **Findings** to review flags separately.
4. To run multiple requests or repeat a saved plan, use **Automated tests**. **Start from URL** prepares ordinary GETs from full endpoint URLs. For an existing contract, use **Imported evidence → Choose files** to select the definition, then **Automated tests → From definitions** to set the base URL. Advanced suites support variables, saved credential profiles, and assertions.
5. Review destinations, role or authentication profile names, and required variables. An unchanged saved plan can be repeated from the desktop or CLI. A changed plan needs fresh approval. Cancellation retains completed and skipped entries.

**Using a VM from Windows.** `127.0.0.1` in a collection refers to the machine making the request. Use the VM’s reachable IP and port on Windows, keep the actual API endpoint path, and leave the source file intact. For example, if the VM serves on `http://192.168.1.20:8888`, enter that as the base URL and enter a documented GET or HEAD path when prompted. Private remote HTTP accepts anonymous GET or HEAD without custom headers, cookies, query strings, or a request body. To use a Bearer token from Windows, use an HTTPS endpoint for that API.

| Result | What to check |
| --- | --- |
| 200 with HTML | You reached a web page. Copy the API path from the documentation or Postman. |
| 401 or 403 | Check the token and authorized role. The result counts as incomplete authenticated coverage. |
| 404 | The server replied. Check the complete path, version prefix, HTTP method, and any IDs. Some APIs also use 404 when a caller lacks access. |
| No HTTP response | Check the shown connection error and confirm that the Windows host can reach the server and port. |

The app stops at redirects and records destinations for review. Adding an in-scope link creates a revised plan for approval. When the plan carries an OpenAPI schema for the observed status and content type, the runner checks the response against it.

## Analyze and investigate saved evidence

Select files or a local folder in **Imported evidence**. Use **Preview files** to check format, counts and warnings. Provide any missing route, API, environment or role context. For CSV, supply a JSON map of normalized field names to source columns. Review the files before clicking **Analyze files**. Offline analysis uses local records and reports missing evidence when an input contains only request definitions.

Accepted formats include Postman Collection v2.1 with nested requests and saved responses, Postman environment metadata, Newman JSON reports with execution records, OpenAPI 3.0 and 3.1 JSON or YAML, HAR 1.2, Insomnia JSON v4, standalone response JSON, and normalized JSON, NDJSON or mapped CSV. Imported scripts are inert. Remote schema references and unsupported formats are reported. Input files are limited to 8 MiB, parsed response bodies to 2 MiB, and runs to 5,000 evidence records. Keep logs and captures on local drives.

Open **Results and evidence** to review findings, coverage and source records. Search a route, header, field, masked value, request ID or finding ID. Use **Open source** to jump to the linked record. Pretty formats the record and explains findings. Raw retains masked source text when it was available and otherwise displays the normalized record. Select the exact imported source to reveal a local original temporarily. Routine copy, report export and provider messages use default masked evidence. Set a finding's review status and add a local note.

Results can be exported as HTML, JSON and CSV. Review the report's gaps and skipped rules before drawing a conclusion. Reports remain available in the project-local workspace. A missing endpoint or role is a coverage gap.

## Apply a policy and verify a fix

Open any stored run, then choose **Policy comparison** and select a versioned JSON or YAML policy. Comparison operates on the same saved evidence. Inspect matched, violated, excepted and unevaluated rules. The most specific applicable field rule wins. At equal scope specificity, a forbid rule takes precedence and the rule ID resolves a remaining tie. Exceptions are valid through the stated expiry date. A severity override changes priority while retaining the violation. A required role that is unavailable leaves the check unevaluated.

Use **Map policy source** to start a draft from selected local Word or text clauses. Inspect the unmapped clauses, review and edit the draft, then validate and compare it. The example support policy forbids `customer.taxId` for the support role. The relaxed example lets you see the effect of another policy on the same data.

Use **Remediation** to review the prioritized plan, its verification steps and affected field. Preview a supported local JSON field removal in a selected source file. Review the masked exact diff, approve the write, and verify it using a comparable new scan. Rollback checks the current fingerprint before restoring the backup. On Windows the local backup uses DPAPI. A patch validated locally still needs comparable evidence to establish a resolution in the affected environment.

## Optional AI assistance

The assistant is disabled by default. The workspace footer displays **AI is off** or **AI is on**. Open **AI assistant**, turn AI on, and choose the provider for your key. Paste your key in the password field or choose **Load key file…** and open a text file containing one key. Choose **Discover chat models**, then send `Hi` and approve the displayed provider request. If you replace the key file, load it again. If a listed model rejects a turn, choose the suggested chat model or try another model your provider supports. Discoverable models and action availability depend on the model and key. [Desktop controls reference](DESKTOP-CONTROLS.md)

Available actions work over local selections. Choose an operation and its resource in the desktop, review the proposed context and effect, then allow the assistant to call the typed action. The assistant can propose a supported operation from a plain-language chat message. Choose Continue with action or Dismiss action. Application code binds the effect to the chosen resources. Use **Cancel job** to cancel an active assistant workflow. Patch application and scope approval require a separate user decision in the corresponding workflow.

## Reproduce the sample as a CI check

Run the commands below from the source folder. Set `$cli` to the extracted portable CLI or substitute `python -B -m apileakguard.cli` for a source run. Use a project-owned test copy.

```powershell
$profile = '.work/ci-profile'
New-Item -ItemType Directory -Force -Path .work/demo | Out-Null
Copy-Item fixtures/support-exposed.json .work/demo/support.json
& $cli --workspace $profile analyze .work/demo/support.json fixtures/expected-only.json --policy fixtures/support-policy.json
$beforeCode = $LASTEXITCODE
$diff = & $cli --workspace $profile fix .work/demo support.json body.customer.taxId | ConvertFrom-Json
& $cli --workspace $profile fix .work/demo support.json body.customer.taxId --apply $diff.before_hash
& $cli --workspace $profile analyze .work/demo/support.json fixtures/expected-only.json --policy fixtures/support-policy.json
$afterCode = $LASTEXITCODE
```

Expect exit code 2 before the fix and 0 afterward. `/customers/2` remains uncovered. Both saved results keep their rule and input identifiers so you can compare them with `compare BEFORE_RUN AFTER_RUN`.

## Rebuild and report verification

Use the PowerShell commands in [the project README](../README.md). Verify the locked x64 wheel hashes and runtime. Confirm the SHA-256 manifest matches the tested executables and portable ZIP. Use synthetic fixtures for bug reports and include the Windows edition and build, architecture, application version, exact source and artifact hashes, and the relevant sanitized test evidence. Start with the [remaining tests](REMAINING-TESTS.md) for the Windows and provider matrix.

Made By ViRuS. © 2026. All rights reserved.
