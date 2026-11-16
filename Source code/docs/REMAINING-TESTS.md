# Remaining APILeakGuard v1.0 tests

Verification status as of 2026-11-15. Live OpenAI and Claude and other Windows configurations are the approved deferrals. Consult the local acceptance ledger for the approved artifact fingerprint and evidence.

## Windows matrix

| Configuration | Implementation target | Verification status and reason |
| --- | --- | --- |
| Windows 11 Pro 22H2 x64, 22621.4317 | Yes | Source and packaged native checks exercised on the host, including portable launch, retained-profile checks, and CLI and GUI workflows. Check the acceptance ledger for exact-snapshot results. |
| Windows 11 Home and Enterprise x64, builds 22631, 26100 and later | Yes | Deferred. No matching edition or build is available on the owner's host. |
| Windows 10 Home, Pro and Enterprise x64, 22H2 build 19045 | Yes | Deferred. No native Windows 10 test host is available. |
| Windows 10 x64, 1809–21H2 including LTSC | Compatibility target where the bundled Qt and Python versions support the build | Deferred. No native hosts are available. Record each build separately. |
| Windows 10 before build 17763 | Unsupported for this package | Qt baseline. |
| Windows x86 | Unsupported for this package | x64 binaries. |
| Windows 11 ARM64 | x64 emulation is a compatibility target. Native ARM64 binaries are outside this package. | Deferred. ARM64 host unavailable. |
| Windows 10 ARM64 | Unsupported for this x64 package | No supported x64 emulation target for this release. |
| Windows 10 and 11 in S mode | Unsupported for the portable executable | The standalone EXE is distributed outside the Microsoft Store. |

Prerequisites are a named Windows host, a standard user, an NTFS test folder, the exact v1.0 checksums, and project-owned synthetic fixtures. Record the edition, build, UBR, physical and process architecture, display scale, artifact fingerprint, and signing status. Extract the ZIP and launch the desktop and CLI. Import the supplied fixtures with AI disabled, run an approved local suite, then reopen the profile in a fresh extraction. Verify the portable ZIP using a fresh directory and confirm the offline scan launches without an external runtime. Verify report and suite retention across portable versions. Capture sanitized evidence and record each outcome against R01 and R04 in the acceptance ledger.

## Provider verification

| Provider | Adapter status | Automated contract | Live check |
| --- | --- | --- | --- |
| OpenAI | Implemented | Passed with mocks | Deferred. A suitable provider credential was outside the approved live test scope. |
| Anthropic Claude | Implemented | Passed with mocks | Deferred. A suitable provider credential was outside the approved live test scope. |
| Google Gemini | Implemented | Passed with mocks | Passed live with `gemini-3.5-flash` for discovery, two plain-language turns, and an app action proposal. |

To run a deferred live check, obtain a provider-approved credential and have quota for an action-capable model. Start a fresh local profile, import `fixtures/support-exposed.json`, explicitly enable the assistant, select the provider, and enter the key into the password field. Discover models for the credential, select a compatible model, and ask it to explain the synthetic finding. Review the masked context and authorize only the local coverage action. Expect a nonempty explanation, a validated action, and the exact selected run summary. Confirm denial with no approval. Run `scripts/Test.ps1` again if an adapter changes. Record the provider, model, status codes, exact build fingerprint, and each outcome under R02. Keep credentials and provider response bodies out of verification evidence.

## Signed-in crAPI lab check

The owner deferred the signed-in VM check. Anonymous requests and the authenticated synthetic fixture passed. To finish the live check, use a trusted HTTPS address for your own crAPI lab and a current token for an authorized test account. In **Manual request**, select **GET**, enter the full `/workshop/api/shop/products` URL, and choose **Bearer token**. Review the plan before sending it. Compare the HTTP status and expected response fields with the same request in Postman. Save only the masked report or a status summary and record the artifact fingerprint in the acceptance ledger.
