# APILeakGuard desktop controls

The workspace menu on the left chooses a page. **Tab** moves focus, **Enter** activates most controls, and **Ctrl+O** opens evidence files. **Ctrl+F** focuses masked evidence search. The footer shows the current AI state, creator credit, version, and GitHub and LinkedIn profile links. **Cancel job** asks the active operation to stop at its next safe boundary.

## Overview

| Control | What it does |
| --- | --- |
| Run practice request | Sends a local GET to the bundled demo API. Shows the HTTP status, sample finding, and masked evidence. |
| Open sample evidence | Scans a bundled saved response to demonstrate offline findings and reports. |
| Send one request · Open workflow | Opens Manual request for one endpoint. |
| Run several requests · Open workflow | Opens Automated tests for URLs or a suite. |
| Review saved responses · Open workflow | Opens Imported evidence for saved responses and logs. |

## Automated tests

| Control | What it does |
| --- | --- |
| Open suite | Opens a local JSON or YAML functional suite and previews its destinations. |
| Start from URL | Prepares one ordinary GET per pasted URL. Review the entire plan. |
| From definitions | Prepares requests from selected OpenAPI files or collections. Supply a reachable base URL. For private HTTP, choose one documented GET or HEAD path. |
| Save suite | Saves the plan by workspace name and offers an optional JSON copy. |
| Load saved suite | Restores a suite by workspace name. |
| Enter variables | Fills placeholders with a JSON object of synthetic test values. |
| Choose run policy | Selects a field policy for the next run. |
| Analyze the selected evidence files in this run | Includes the currently selected local evidence with the functional run. |
| Approve and run | Shows the exact request plan and starts it after approval. |
| Rerun approved suite | Starts the unchanged approved plan. An edited plan needs fresh approval. |
| Review discovered links | Opens pending links from the current run. |

## Imported evidence

| Control | What it does |
| --- | --- |
| Choose files | Opens the file picker for one or more local evidence files. Drag and drop works on this page too. |
| Choose folder | Selects a directory of evidence files. |
| Remove selection | Clears the current file selection. |
| Preview files | Shows recognized formats, record counts and warnings. |
| Analyze files | Runs the local scanner and opens its report. |
| Prepare functional suite | Opens the approved scope prompt for request definitions. |
| Choose local schema references | Selects JSON or YAML files a contract may reference by filename. |
| Clear references | Clears the selected local schema reference files. |
| API, Environment, Role, Route, CSV columns | Fill missing context or map CSV columns to the normalized fields. |

## Manual request

| Control | What it does |
| --- | --- |
| Method and Endpoint URL | Sets the HTTP method and full API URL. With an explicit base URL, you can enter a relative path. |
| Authentication | Selects No authentication, an in-memory Bearer token, or a named credential saved in Settings. |
| Token or Saved profile | Supplies the token for the current plan or the stored profile name. Authenticated remote requests use HTTPS. |
| Show advanced request settings | Shows optional base URL, API, environment, role, headers, query, variables, and body fields. The JSON fields accept JSON objects. Body format selects text, JSON, or form encoding. |
| Preview request | Opens the request plan. After you review the URL, method and authentication, choose Approve and run. |

An explicitly entered private IPv4 HTTP endpoint allows anonymous GET or HEAD without credentials, cookies, custom headers, query strings, or a body. The preview identifies that connection.

## Projects and suites

**Import project scopes** loads a versioned local project definition and asks you to review each scope. **Refresh workspace inventory** reloads workspace project and suite details.

## Results and evidence

| Control | What it does |
| --- | --- |
| Search masked evidence | Searches the current category. Use filters such as `role:support status:200`. |
| Result category | Switches among findings, evidence, requests, coverage, links, remediation and summary. |
| Pretty or Raw | Switches views while keeping the selected record. |
| Open source | Jumps to the evidence behind the selected finding. |
| Reveal original | Requires the exact local source file and confirmation. Closes back to masked evidence. |
| Track finding | Saves a review status and local note. |
| Export report | Saves HTML, JSON or CSV. Review the destination before replacing a file. |
| Add selected link to plan | Adds a reviewed, in-scope link to the pending suite for fresh approval. |
| Export discovered links | Writes the masked candidate list. |

## Policy comparison

**Choose policy** applies a selected JSON or YAML policy to the current saved run. **Compare with sample policy** applies the strict support example. **Compare relaxed example** applies the second example and shows differences on the same run. **Edit policy** validates and saves or applies a local draft. **Map policy source** helps turn a selected Word or text clause into a draft rule. **Export comparison** writes the current masked comparison.

## Run history

Select a stored run. **Open selected run** or double-click loads it. **Refresh** reloads recent runs.

## Remediation

**Preview local fix** asks for a local JSON file and field and shows the masked diff. **Apply fix** confirms the selected edit. **Verify with new evidence** rescans the edited evidence and compares its result to the original. **Rollback** restores the original backup when the file still matches the applied edit.

## AI assistant

**Turn AI on for this session** enables chat and changes the footer. Choose a **Provider**. Enter the **Session key** in the masked field or choose **Load key file…** to read one key from a text file. **Discover chat models** lists candidates and suggests a model. You can also type a **Model** ID. Type into **Chat message** and press **Enter** or click **Send**. The chat remembers recent turns. **Include the current run’s masked summary** adds that summary to the provider request. **Review data shared** previews the outbound chat context. **New chat** clears the session transcript. Turning AI off also clears it.

When the assistant proposes an app operation, **Continue with action** and **Dismiss action** stay beside the message composer while you scroll. **Continue with action** uses the named workflow and the resources already selected in the app. **Dismiss action** discards the proposal. Prompt examples include “Open the sample evidence,” “Review the run coverage,” “Compare this run with a policy,” and “Export this report.” Live requests still go through the desktop’s plan review and Send controls. File pickers and confirmation dialogs handle local destinations and edits.

If sending fails, the reason appears above the message box. Your draft stays editable. Follow the displayed guidance and select **Send** to try again.

## Settings

**Theme** chooses System, Light, or Dark. **Save credential** stores an API identity for a project, API, environment, and role profile. **Remove credential** removes the selected local entry after confirmation. Use the separate session key field on the AI page for the AI provider.
