# APILeakGuard v1.0

APILeakGuard runs authorized functional API tests and checks ordinary responses and saved evidence for sensitive data exposure. The Windows desktop and console applications share the same offline scanner, policies, and local run history.

See the [user handbook](docs/HANDBOOK.md) for the walkthrough, [desktop controls](docs/DESKTOP-CONTROLS.md), and [app operation access](docs/OPERATIONS.md) for desktop, CLI and assistant permissions.

## Windows setup

Target Windows 10 and 11 x64. See [remaining tests](docs/REMAINING-TESTS.md) for the tested configuration, Windows matrix, and provider status. The unsigned artifacts bundle Python and the runtime libraries. Extract the portable ZIP to a writable folder and keep its `_internal` directory beside the executables.

```powershell
# From the extracted APILeakGuard-v1.0 folder
.\apileakguard-cli.exe --version
.\APILeakGuard.exe --workspace .\local-profile
```

Use a separate writable workspace for testing. Portable mode uses the adjacent `profile` directory when `portable.profile` is present. Keep that folder when moving to a newer extracted build.

## Desktop quick start

1. Open **Overview** and choose **Run practice request**. Follow the HTTP result to the sample finding and its masked response.
2. Open **Manual request**, enter the full URL of an authorized API endpoint, and choose its HTTP method and authentication. Choose **Preview request**, then **Approve and run**. Check the HTTP result and the findings independently.
3. Use **Automated tests** to start from authorized URLs, map selected definitions to a reachable server, or open a saved suite. Review the plan before sending it.
4. Use **Open sample evidence** to practice the offline workflow. Try **Open source**, **Compare with sample policy**, and the **Remediation** screen. Use **Imported evidence** for your own saved responses and logs.

## CLI quick start

```powershell
$cli = '.\apileakguard-cli.exe'
& $cli --workspace .\local-profile analyze .\fixtures\support-exposed.json --policy .\fixtures\support-policy.json
& $cli --workspace .\local-profile runs
& $cli --workspace .\local-profile policy-validate .\fixtures\support-policy.json
& $cli --workspace .\local-profile --help
```

Exit codes are `0` for success, `2` for findings or failed assertions, `3` for partial or cancelled work, and `4` for invalid input or local errors. `preview` prints the exact suite fingerprint. `approve` accepts that fingerprint and saves approval locally. `run` requires an unchanged approved plan. `request` and `run` can connect to selected APIs. Model discovery and chat connect to the selected provider only when enabled. Offline analysis, policy comparison and reports operate on local data.

## Imports and credentials

Supported inputs include OpenAPI 3.0 and 3.1 JSON and YAML, nested Postman Collection v2.1 and saved examples, Postman variable names, Newman JSON with `run.executions`, HAR 1.2, Insomnia JSON v4, and native JSON, NDJSON or mapped CSV. Preview the import for format and feature limits. File and body limits are 8 MiB and 2 MiB. Imported scripts and remote references are inert.

In **Manual request**, select **Bearer token** to use an existing access token in memory for the current plan. Use HTTPS for authenticated remote APIs. Use named credential profiles in **Settings** for repeat tests or different authorized roles. The app reports authentication errors as incomplete coverage. Windows DPAPI protects saved credentials for the current user. Keep provider keys, API secrets and private captures out of suites, exports and support discussions.

## Build and test

```powershell
.\scripts\Bootstrap.ps1 -BasePython C:\path\to\python.exe
.\scripts\Test.ps1
.\scripts\Build.ps1
```

The reference toolchain uses Python 3.12.14 x64, PySide6 Essentials 6.8.3 and the platform-specific wheel hashes in `requirements-win-x64.lock`. Build and test state is project-local. The build creates one portable release ZIP, a release manifest and SHA-256 sums. The source snapshot stays in the local build workspace. Keep the shared runtime files with both executables.

## Contributing

Use the [remaining tests](docs/REMAINING-TESTS.md) to reproduce compatibility and provider checks. Include the exact artifact fingerprint and use only synthetic or authorized masked evidence in reports.

## Credits

Made By ViRuS. © 2026. All rights reserved.

[GitHub](https://github.com/The-Real-Virus) · [LinkedIn](https://www.linkedin.com/in/syed-muhammad-shah)
