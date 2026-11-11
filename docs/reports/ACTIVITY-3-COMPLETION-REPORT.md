# Activity 3 Completion Report · SafeVault Capstone

| Document Metadata | Value |
|---|---|
| **Activity ID** | Course 8 Capstone · Activity 3 (C8-ACT3) |
| **Title** | Security Debugging, Vulnerability Remediation & Final Capstone Summary |
| **Author** | Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`) |
| **Specialization** | Microsoft Full Stack Developer Specialization |
| **Course** | Course 8: Security and Authentication |
| **Status** | Completed on `main` (`c670798`) |
| **Pull Requests Landed** | [#5](https://github.com/jdsaire/fullstack_c8_safevault/pull/5) (`52227f2`), [#6](https://github.com/jdsaire/fullstack_c8_safevault/pull/6) (`5a32c60`), [#7](https://github.com/jdsaire/fullstack_c8_safevault/pull/7) (`c670798`) |
| **Live Demonstration** | [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/) |
| **Date** | November 11, 2026 |

---

## 1. Executive Summary

Activity 3 of the SafeVault Capstone completes the third and final milestone of the Microsoft Full Stack Developer Specialization security curriculum. Building upon the baseline input validation and parameterized data access of Activity 1 and the cryptographic authentication, salted BCrypt hashing, and Role-Based Access Control (RBAC) of Activity 2, Activity 3 conducts a comprehensive **codebase security audit**, **vulnerability debugging and remediation cycle**, **28-test automated regression suite expansion**, and **final capstone architecture and AI assistance disclosure evaluation**.

Activity 3 identified, triaged, and remediated four codebase vulnerabilities (`V1`–`V4` `[M]`) alongside two baseline demonstration patterns (`S1`–`S2` `[SIM]`). The automated NUnit security test suite was expanded from 18 to **28 passing tests** (`[M]`), and the user interface was extended with a dedicated interactive debugging workspace ([`cycle7-debug.html`](../../cycle7-debug.html)) and an idle-state refined multi-cycle verification hub ([`index.html`](../../index.html)).

### Milestone Deliverables Achieved
- **Codebase Vulnerability Remediation (`[M]`)**: Audited all layers of SafeVault and resolved four distinct vulnerabilities:
  1. *V1 (XSS in Validation Error Strings)*: Enforced HTML entity encoding on user input before reflection in validation error messages and hardened regex guards against embedded tags, event handlers, and protocol handlers in [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs).
  2. *V2 (Wildcard SQL LIKE Denial of Service / Dump)*: Implemented `EscapeSqlLikeWildcards` in [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) and wired parameterized query binding with explicit escape clauses (`LIKE @SearchPattern ESCAPE '\'`) in [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs).
  3. *V3 (Pipe Delimiter Injection in Session Tokens)*: Sanitized usernames and role claims in [`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs) to prevent claim delimiter injection (`|`), preserving HMAC-SHA256 token integrity.
  4. *V4 (Cryptographic Work Factor Boundary Hardening)*: Added bounds checking (`4 <= workFactor <= 31`) in [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs) to eliminate denial of service from excessive CPU exhaustion while ensuring sufficient cryptographic work factor.
- **Automated Regression Test Suite Expansion (`[M]`)**: Implemented [`Tests/TestVulnerabilityRemediation.cs`](../../Tests/TestVulnerabilityRemediation.cs) containing 10 new NUnit test fixtures covering edge cases, null bytes, oversized inputs, delimiter injection, wildcard escaping, and end-to-end regression across all layers. The full test suite executes **28 automated tests** in `6.83 s` (`0` warnings, `0` errors) (`[M]`).
- **Interactive Remediation & Debugging Workspace (`[SIM]` Client Fallback)**: Built [`cycle7-debug.html`](../../cycle7-debug.html) offering an interactive vulnerability probe simulator, live before/after remediation diffs, an interactive parameterized directory search panel with real-time wildcard escaping inspection, and a vulnerability audit ledger.
- **Multipage Idle Arrival State Refinement (`[SIM]`)**: Eliminated prefilled input values, automatic DOM execution on load, and default diagnostic toasts across Cycles 1–7. Standardized all initial evaluation panels to `Idle` / `// Awaiting form submission...` and normalized hub cards with sequential ordering (1–7) and solid light blue call-to-action buttons.
- **Comprehensive Documentation & AI Disclosure (`[M]`)**: Updated [`README.md`](../../README.md) with Activity 3 remediation architecture, the 4-vulnerability ledger, and the complete Criterion C6 capstone evaluation and generic AI assistance disclosure.

---

## 2. Course 8 Capstone Rubric Alignment

The table below quotes the six Course 8 Capstone rubric criteria verbatim and records how Activity 3 fulfills and finalizes each criterion across the repository:

| Criterion | Points | Question | Activity 3 Scope & Repository Evidence |
|---|---|---|---|
| C1 | 5 | Did you create a GitHub repository for your project? | Public repository [`jdsaire/fullstack_c8_safevault`](https://github.com/jdsaire/fullstack_c8_safevault) finalized across Pull Requests [#5](https://github.com/jdsaire/fullstack_c8_safevault/pull/5) (`52227f2`), [#6](https://github.com/jdsaire/fullstack_c8_safevault/pull/6) (`5a32c60`), and [#7](https://github.com/jdsaire/fullstack_c8_safevault/pull/7) (`c670798`) on `.NET 8` solution [`SafeVault.sln`](../../SafeVault.sln) with clean git commit history, verified GitHub Pages deployment, and zero build warnings (`[M]`). |
| C2 | 5 | Did you use an AI environment to generate secure code for input validation and SQL injection prevention? | An AI environment assisted in implementing and hardening input validation, sanitization, and SQL injection prevention across [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs), [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs), and [`webform.html`](../../webform.html) (`[M]`), including parameterized LIKE search with wildcard escaping (`EscapeSqlLikeWildcards`) and strict RFC 5322 regex validation (`[M]`). |
| C3 | 5 | Did you use an AI environment to implement authentication and authorization mechanisms, including role-based access control (RBAC)?? | An AI environment assisted in implementing salted BCrypt password hashing (`BCrypt.Net-Next`, work factor 12) in [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs), constant-time authentication and anti-enumeration in [`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs), and HMAC-SHA256 session token issuance and role-based access control for `Admin`, `Auditor`, and `User` roles in [`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs) and [`src/SafeVault/Program.cs`](../../src/SafeVault/Program.cs) (`[M]`). |
| C4 | 5 | Did you debug and resolve security vulnerabilities such as SQL injection and XSS? | Conducted end-to-end vulnerability debugging across all application layers, identifying and fixing 4 distinct vulnerabilities (`V1` email XSS via unencoded error reflection, `V2` wildcard SQL LIKE dump, `V3` pipe claim delimiter injection in bearer tokens, `V4` BCrypt work factor bounds validation) and demonstrating baseline vulnerability remediations (`S1` SQL concatenation vs parameterization, `S2` innerHTML vs HTML encoding) in [`cycle7-debug.html`](../../cycle7-debug.html) (`[M]` and `[SIM]`). |
| C5 | 5 | Did you generate and execute tests to verify the application's security? | An AI environment assisted in generating 10 security regression tests in [`Tests/TestVulnerabilityRemediation.cs`](../../Tests/TestVulnerabilityRemediation.cs) executed alongside Activity 1 (`Tests/TestInputValidation.cs`, 8 tests) and Activity 2 (`Tests/TestAuthAndRbac.cs`, 10 tests), achieving **28/28 automated NUnit tests passing** (`0` warnings, `0` errors, `6.83 s` duration) (`[M]`). |
| C6 | 5 | Did you include a brief summary of the vulnerabilities identified, the fixes applied, and how the AI environment assisted in the debugging process? | Formulated the complete capstone security evaluation in [`README.md`](../../README.md) and [`ACTIVITY-3-COMPLETION-REPORT.md`](ACTIVITY-3-COMPLETION-REPORT.md), providing detailed vulnerability breakdowns, root-cause analyses, code fixes, regression assertions, and a generic attestation of how an AI environment assisted in vulnerability diagnosis, patch generation, and test creation (`[M]`). |

---

## 3. Chronological Evolution & Commit History

Activity 3 and its subsequent review and UI refinements were completed across three pull requests landed on `main`:

### Pull Request #5: Activity 3 Security Debugging & Vulnerability Remediation (`52227f2`)
Branch `activity-3-security-debugging` was created from `main` (`8b0fe9d`) and merged via Pull Request [#5](https://github.com/jdsaire/fullstack_c8_safevault/pull/5) across 6 atomic commits:

1. **`33ee98b` — Harden input validation, XSS sanitization, and work factor bounds (`[M]`)**
   - Implemented `EscapeSqlLikeWildcards` in [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) escaping `%`, `_`, and `\` with backslashes.
   - Enforced HTML entity encoding (`WebUtility.HtmlEncode`) on reflected error strings and strengthened email regex to block script tags and protocol vectors (`javascript:`, `data:`).
   - Enforced bounds checking (`4 <= workFactor <= 31`) on `PasswordHasher.HashPassword` in [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs).
2. **`975209f` — Remediate repository schema uniqueness and add parameterized search (`[M]`)**
   - Extended [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs) with `SearchUsersAsync` implementing parameterized `LIKE @SearchPattern ESCAPE '\'` queries.
   - Enforced column identifier whitelist validation in `EnsureColumnExists` preventing SQL syntax injection during schema migrations.
3. **`c97c8bc` — Harden session token claims, security headers, and audit endpoints (`[M]`)**
   - Hardened `IssueSessionToken` and `ValidateSessionToken` in [`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs) to reject usernames containing pipe delimiters (`|`).
   - Added security response headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`) and registered `GET /api/users/search` and `GET /api/audit/vulnerabilities` in [`src/SafeVault/Program.cs`](../../src/SafeVault/Program.cs).
   - Created [`src/SafeVault/Services/SecurityAuditService.cs`](../../src/SafeVault/Services/SecurityAuditService.cs) returning a structured ledger of measured and simulated findings.
4. **`7f7ba1c` — Add NUnit regression tests for SQLi, XSS, and auth remediations (`[M]`)**
   - Created [`Tests/TestVulnerabilityRemediation.cs`](../../Tests/TestVulnerabilityRemediation.cs) containing 10 NUnit tests verifying all Activity 3 remediations (`28/28` cumulative tests passing).
5. **`8d8f7f6` — Add Cycle 7 security debugging workspace and 28-test runner (`[SIM]` Client Fallback)**
   - Created [`cycle7-debug.html`](../../cycle7-debug.html) featuring the interactive vulnerability probe simulator, before/after diffs, and parameterized directory search.
   - Updated [`cycle4-tests.html`](../../cycle4-tests.html), [`index.html`](../../index.html), and navigation headers across all workspaces to support Cycle 7.
6. **`af600af` — Add Activity 3 remediation architecture and C6 summary to README**
   - Documented Activity 3 vulnerability fixes, Criterion C6 disclosure, and the 28-test verification ledger in [`README.md`](../../README.md).

### Pull Request #6: Review Run R1 Report Corrections (`5a32c60`)
Branch `review-reports-r1` was merged via Pull Request [#6](https://github.com/jdsaire/fullstack_c8_safevault/pull/6) to align existing documentation with the capstone rubric:
- `f16dbff`: Standardized [`ACTIVITY-1-COMPLETION-REPORT.md`](ACTIVITY-1-COMPLETION-REPORT.md) to quote the capstone rubric table verbatim, removed self-awarded scores, and corrected method references.
- `b728e1d`: Standardized [`ACTIVITY-2-COMPLETION-REPORT.md`](ACTIVITY-2-COMPLETION-REPORT.md) to quote the capstone rubric table verbatim, removed self-awarded scores, and corrected PR #4 attribution and method identifiers.
- `d581f21`: Updated [`README.md`](README.md) reports index to document the pull request delivery protocol and status.

### Pull Request #7: UI/UX Idle-State & Hub Refinements (`c670798`)
Branch `ui-ux-idle-state-refinement` was merged via Pull Request [#7](https://github.com/jdsaire/fullstack_c8_safevault/pull/7) to ensure an uncluttered, idle arrival user experience:
- `14d7b88`: Reordered hub cards on [`index.html`](../../index.html) sequentially (`Cycle 1` through `Cycle 7`), standardized all action buttons to solid light blue (`btn-primary`), relocated the scope disclosure to the bottom before the footer, and removed the redundant hub telemetry panel.
- `14fc8ca`: Cleared prefilled inputs and removed `DOMContentLoaded` auto-execution across Cycles 1–4, ensuring forms start empty and panels display `// Awaiting form submission...`.
- `5ca0654`: Cleared prefilled inputs and removed auto-executions across Cycles 5–7, and disabled `sessionStorage` telemetry prefilling in [`js/safevault.js`](../../js/safevault.js) so telemetry inspectors always arrive in an idle state.

---

## 4. Technical Debugging Deep Dive & Root Cause Analysis (`[M]` vs. `[SIM]`)

Activity 3 audited the entire SafeVault codebase to identify security vulnerabilities, analyze their root causes, apply defensive patches, and verify the fixes with automated tests:

### Vulnerability 1 (V1 `[M]`): XSS Reflection in Input Validation Error Messages
- **Vulnerability Description**: During user intake, when a submitted username or email failed validation, the unencoded raw user input was embedded directly into the error response message string returned to the client. If an attacker submitted an email containing HTML/JavaScript tags (e.g. `"<script>alert(1)</script>"@evil.com`), the returned error message could execute in contexts expecting plain text or non-escaped HTML.
- **Root Cause**:
  ```csharp
  // Flawed Implementation
  return (false, $"Email '{rawEmail}' is invalid.");
  ```
- **Remediation**:
  1. Enforced HTML entity encoding via `WebUtility.HtmlEncode(input)` before formatting error messages.
  2. Hardened email regex validation in [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) to reject angle brackets (`<`, `>`), quotes, semicolons, and protocol schemes (`javascript:`, `data:`).
- **Verification**: Verified by `TestEmailValidation_RejectsEmbeddedXssAndSqlPayloads` and `TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols` (`[M]`).

### Vulnerability 2 (V2 `[M]`): Wildcard SQL LIKE Denial of Service & Directory Dump
- **Vulnerability Description**: In user directory searches using SQL `LIKE`, unescaped wildcard characters (`%` and `_`) allowed an attacker to bypass search filters. Submitting a single `%` character matched all records in the table, bypassing pagination and causing excessive database workload.
- **Root Cause**:
  ```csharp
  // Flawed Query Generation
  command.CommandText = "SELECT * FROM Users WHERE Username LIKE @Term;";
  command.Parameters.AddWithValue("@Term", "%" + userInput + "%");
  ```
  If `userInput` contains `%`, the resulting pattern `%%%` matches every user in the database without literal matching.
- **Remediation**:
  1. Implemented `InputValidator.EscapeSqlLikeWildcards(string input)` to escape `\`, `%`, and `_` with a backslash.
  2. Bound the escaped pattern using `SqliteParameter` and appended the SQLite escape clause:
  ```csharp
  command.CommandText = @"SELECT Id, Username, Email, Role, CreatedAt 
                          FROM Users 
                          WHERE Username LIKE @SearchPattern ESCAPE '\' 
                             OR Email LIKE @SearchPattern ESCAPE '\';";
  command.Parameters.Add(new SqliteParameter("@SearchPattern", $"%{escaped}%"));
  ```
- **Verification**: Verified by `TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards` (`[M]`).

### Vulnerability 3 (V3 `[M]`): Pipe Delimiter Injection in HMAC Bearer Tokens
- **Vulnerability Description**: The session token payload format utilized pipe characters as field separators: `{userId}|{username}|{role}|{expiryUnix}`. An attacker who registered a username containing pipe characters (e.g., `alice|Admin|9999999999`) could manipulate the token segment count and escalate privileges upon token deserialization.
- **Root Cause**: Unsanitized payload string concatenation without delimiter escaping:
  ```csharp
  var payload = $"{userId}|{username}|{role}|{expiryUnix}";
  ```
- **Remediation**:
  1. Updated `AuthorizationService.IssueSessionToken` to reject or sanitize usernames and roles containing pipe characters (`|`).
  2. Hardened token deserialization in `ValidateSessionToken` to verify exact segment counts and enforce strict role validation against the `Role` enum whitelist (`Admin`, `Auditor`, `User`).
- **Verification**: Verified by `TestSessionToken_RejectsPipeDelimiterInjectionInUsername` (`[M]`).

### Vulnerability 4 (V4 `[M]`): Unbounded BCrypt Work Factor Denial of Service
- **Vulnerability Description**: The password hashing interface accepted an arbitrary integer for the BCrypt work factor. Submitting a high work factor (e.g., `31`) would trigger $2^{31}$ Blowfish rounds, hanging the server CPU for days and inducing a denial-of-service condition.
- **Root Cause**: Lack of boundary validation on the work factor parameter.
- **Remediation**: Enforced standard cryptographic bounds in [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs):
  ```csharp
  if (workFactor < 4 || workFactor > 31)
  {
      throw new ArgumentOutOfRangeException(nameof(workFactor), "Work factor must be between 4 and 31.");
  }
  ```
  SafeVault standardizes on a work factor of `12` ($2^{12} = 4,096$ rounds) for all production hashing.
- **Verification**: Verified by `TestPasswordHasher_EnforcesStandardWorkFactorBounds` (`[M]`).

### Simulated Baselines & UI Refinements (`[SIM]`)
- **Simulated SQL Concatenation vs. Parameterization (S1 `[SIM]`)**: In [`cycle7-debug.html`](../../cycle7-debug.html), side-by-side comparison illustrates how dynamic string concatenation (`SELECT * FROM Users WHERE Username = '` + input + `'`) is exploited by tautologies (`' OR '1'='1`), while `SqliteParameter` treats the input as an inert string literal.
- **Simulated Unescaped innerHTML vs. HtmlEncode (S2 `[SIM]`)**: Demonstrates how direct `element.innerHTML = payload` executes embedded `<img src=x onerror=...>`, while entity encoding converts tokens to safe `&lt;` and `&gt;` text nodes.
- **Interactive Idle State Normalization (PR #7 `[SIM]`)**: Ensures that users encounter a fresh, non-polluted workspace upon navigating to any cycle page. Forms arrive empty, all panels display `// Awaiting form submission...`, and no automated tests or diagnoses run until explicitly triggered by the user.

---

## 5. Security Telemetry & Automated Test Suite Audit (`[M]`)

### Measured NUnit Automated Test Results (`28/28` Passed — `[M]`)
The complete test suite executes 28 automated test assertions across three test fixtures:

```text
Test run for Tests/bin/Release/net8.0/Tests.dll (.NETCoreApp,Version=v8.0)
VSTest version 17.11.2 (x64)

Starting test execution, please wait...
A total of 1 test files matched the specified pattern.
NUnit Adapter 4.5.0.0: Test execution started
Running all tests in Tests/bin/Release/net8.0/Tests.dll
   NUnit3TestExecutor discovered 28 of 28 NUnit test cases using Current Discovery mode, Non-Explicit run

  Passed TestLogin_InvalidPassword_RejectsWithUnauthorized [504 ms]
  Passed TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration [580 ms]
  Passed TestLogin_SqlInjectionPayloads_AreNeutralized [1 s]
  Passed TestLogin_ValidCredentials_AuthenticatesAndIssuesSignedToken [135 ms]
  Passed TestPasswordHashing_GeneratesUniqueSaltsAndVerifiesCorrectly [1 s]
  Passed TestRbac_AdminRole_GrantedAccessToAdminDashboardAndRoleManagement [193 ms]
  Passed TestRbac_AuditorRole_GrantedAuditLogsButDeniedAdminDashboard [129 ms]
  Passed TestRbac_InvalidRoleOrWeakPassword_RejectedDuringRegistration [2 ms]
  Passed TestRbac_StandardUserRole_DeniedAccessToAdminDashboard [146 ms]
  Passed TestRbac_UnauthenticatedOrTamperedToken_DeniedWith401 [135 ms]
  Passed TestForSQLInjection [5 ms]
  Passed TestForXSS [2 ms]
  Passed TestInvalidInput_FailsValidation("","user@test.com","Username is required.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("ab","user@test.com","Username must be between 3 and 50 characters.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("invalid user name with spaces","user@test.com","Username contains invalid characters.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("valid_user","","Email is required.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("valid_user","not-an-email","Email format is invalid.") [< 1 ms]
  Passed TestValidInput_PassesValidation [< 1 ms]
  Passed TestAuthAndLookup_RejectsNullBytesAndOversizedPayloads [567 ms]
  Passed TestEmailValidation_RejectsEmbeddedXssAndSqlPayloads [2 ms]
  Passed TestEndToEndRegression_AllSecurityLayersRemainIntact [203 ms]
  Passed TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards [1 ms]
  Passed TestPasswordHasher_EnforcesStandardWorkFactorBounds [5 ms]
  Passed TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols [1 ms]
  Passed TestSchemaMigration_RejectsUnwhitelistedColumnIdentifier [< 1 ms]
  Passed TestSecurityAuditService_DistinguishesMeasuredAndSimulatedFindings [4 ms]
  Passed TestSessionToken_RejectsPipeDelimiterInjectionInUsername [< 1 ms]
  Passed TestUniqueUsernameConstraint_PreventsDuplicateIntakeAndRegistration [3 ms]

Test Run Successful.
Total tests: 28
     Passed: 28
 Total time: 6.8322 Seconds
```

### Cumulative Test Fixture Breakdown

| Test Fixture | Activity Introduced | Test Count | Security Focus & Scope | Execution Status |
|---|---|---|---|---|
| [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs) | Activity 1 | 8 | SQLi tautologies, stacked DROP TABLE, inline comments, script/event XSS, regex validation | `8 / 8` Passed (`[M]`) |
| [`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs) | Activity 2 | 10 | BCrypt unique salts, constant-time login, anti-enumeration, SQLi login defense, RBAC gates (200/401/403) | `10 / 10` Passed (`[M]`) |
| [`Tests/TestVulnerabilityRemediation.cs`](../../Tests/TestVulnerabilityRemediation.cs) | Activity 3 | 10 | Email XSS reflection, wildcard LIKE escaping, pipe claim injection, work factor bounds, null bytes, regression | `10 / 10` Passed (`[M]`) |
| **Total Cumulative Suite** | **Activities 1–3** | **28** | **Comprehensive Full-Stack Defense-in-Depth Verification** | **`28 / 28` Passed (`[M]`)** |

---

## 6. Component Architecture

```text
fullstack_c8_safevault/
├── SafeVault.sln                           # .NET 8 multi-project solution [M]
├── database.sql                            # Hardened SQLite schema (Unique Users, Constraints) [M]
├── index.html                              # 7-Cycle Verification Hub (Ordered 1-7, Solid Buttons) [SIM]
├── cycle1-intake.html                      # Cycle 1: Legitimate Intake & Parameterized Insert [SIM]
├── cycle2-sqli.html                        # Cycle 2: SQLi Defense Inspector (Idle Arrival) [SIM]
├── cycle3-xss.html                         # Cycle 3: Dual-Stage XSS Sanitization (Idle Arrival) [SIM]
├── cycle4-tests.html                       # Cycle 4: 28-Test Automated NUnit Suite Runner [SIM]
├── cycle5-auth.html                        # Cycle 5: Salted BCrypt & Constant-Time Login [SIM]
├── cycle6-rbac.html                        # Cycle 6: RBAC Policy Enforcement & Admin Dashboard [SIM]
├── cycle7-debug.html                       # Cycle 7: Vulnerability Remediation & Search Audit [SIM]
├── webform.html                            # Standalone intake demonstration [SIM]
├── css/
│   └── styles.css                          # Shared WCAG 2.1 AAA dark slate stylesheets [SIM]
├── js/
│   └── safevault.js                        # Dual-mode security engine & idle telemetry manager [SIM]
├── docs/
│   └── reports/
│       ├── README.md                       # Activity reports index & PR protocol [M]
│       ├── ACTIVITY-1-COMPLETION-REPORT.md # Activity 1 completion report [M]
│       ├── ACTIVITY-2-COMPLETION-REPORT.md # Activity 2 completion report [M]
│       └── ACTIVITY-3-COMPLETION-REPORT.md # Activity 3 completion report (this document) [M]
├── src/SafeVault/
│   ├── SafeVault.csproj                    # .NET 8 Web API & BCrypt.Net-Next package [M]
│   ├── Program.cs                          # Minimal API endpoints & security headers [M]
│   ├── Data/
│   │   └── UserRepository.cs               # Parameterized SQLite queries & LIKE escaping [M]
│   ├── Models/
│   │   └── UserSubmission.cs               # DTOs, SecurityAuditRecord, & UserRecord [M]
│   └── Services/
│       ├── AuthService.cs                  # Constant-time login & anti-enumeration [M]
│       ├── AuthorizationService.cs         # RBAC policy evaluator & pipe-safe HMAC tokens [M]
│       ├── InputValidator.cs               # Regex validation, HTML encoding & LIKE escaping [M]
│       ├── PasswordHasher.cs               # BCrypt cost-12 hashing & bounds validation [M]
│       └── SecurityAuditService.cs         # Audit service for measured/simulated findings [M]
└── Tests/
    ├── Tests.csproj                        # NUnit test project [M]
    ├── TestInputValidation.cs              # 8 Activity 1 input validation & SQLi tests [M]
    ├── TestAuthAndRbac.cs                  # 10 Activity 2 authentication & RBAC tests [M]
    └── TestVulnerabilityRemediation.cs     # 10 Activity 3 vulnerability remediation tests [M]
```

---

## 7. Scope Boundaries: Activities 1, 2, and 3 Complete Capstone Scope

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        COURSE 8 SAFEVAULT CAPSTONE: FULL SCOPE                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  ✔ Activity 1: Input Validation, HTML Entity Encoding, Parameterized SQLite Queries    │
│  ✔ Activity 2: Salted BCrypt Hashing (Cost 12), Constant-Time Auth & Anti-Enumeration  │
│  ✔ Activity 2: HMAC-SHA256 Session Tokens & Role-Based Access Control (RBAC)           │
│  ✔ Activity 3: Security Vulnerability Debugging & Remediation Audit (V1–V4, S1–S2)     │
│  ✔ Activity 3: Parameterized Directory Search with Wildcard LIKE Escaping             │
│  ✔ Activity 3: 28-Test Automated NUnit Security Suite (100% Passing, 0 Warnings)       │
│  ✔ Activity 3: 7 Guided Execution Workspaces (Cycles 1–7) & Central Hub                │
│  ✔ Activity 3: Idle Arrival UX Refinement, Telemetry Quarantine & Scope Relocation     │
│  ✔ Activity 3: Complete Rubric Alignment & Generic AI Assistance Disclosure Summary    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Artifact & Verification Audit Ledger

| Artifact Category | Identifier / Target | Location / Hash | Provenance & Status |
|---|---|---|---|
| **Pull Request #1** | Activity 1 Input Validation & SQLi | Merged at `4654021` | `[M]` Merged by `jdsaire` |
| **Pull Request #2** | Activity 1 UI & Accessibility Refinement | Merged at `3a87c50` | `[M]` Merged by `jdsaire` |
| **Pull Request #3** | Activity 1 Multipage Debug & Telemetry Quarantine | Merged at `eb99ab5` | `[M]` Merged by `jdsaire` |
| **Pull Request #4** | Activity 2 Authentication & RBAC | Merged at `feedc6a` | `[M]` Merged by `jdsaire` |
| **Pull Request #5** | Activity 3 Security Debugging & Remediation | Merged at `52227f2` | `[M]` Merged by `jdsaire` |
| **Pull Request #6** | Review Run R1 Report Corrections | Merged at `5a32c60` | `[M]` Merged by `jdsaire` |
| **Pull Request #7** | UI/UX Idle-State & Hub Refinements | Merged at `c670798` | `[M]` Merged by `jdsaire` |
| **Release Build** | `dotnet build SafeVault.sln -c Release` | `0` warnings, `0` errors | `[M]` Verified |
| **NUnit Test Suite** | `dotnet test SafeVault.sln -c Release` (28 tests across 3 fixtures) | `28` passed, `0` failed (`6.83 s`) | `[M]` Verified |
| **Live Demonstration** | Multipage GitHub Pages Deployment (`index.html`, `cycle1–7`, `webform.html`) | `https://jdsaire.github.io/fullstack_c8_safevault/` | `[SIM]` Client-side simulation fallback |

---

## 9. Author & AI Assistance Disclosure Attestation

- **Sole Author**: Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`).
- **AI Assistance Summary (Criterion C6)**:
  In accordance with the Course 8 Capstone evaluation guidelines, an AI environment assisted across the project lifecycle:
  1. *Input Validation & SQLi Prevention (Criterion C2)*: An AI environment assisted in designing regular expressions for input sanitization, generating HTML entity encoding routines, and structuring parameterized `SqliteParameter` commands in [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) and [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs).
  2. *Authentication & RBAC (Criterion C3)*: An AI environment assisted in implementing BCrypt password hashing with unique salt generation in [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs), structuring constant-time authentication with dummy-hash anti-enumeration in [`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs), and generating HMAC-SHA256 bearer token issuance and role-based route gate evaluations for `Admin`, `Auditor`, and `User` roles in [`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs).
  3. *Security Debugging & Vulnerability Remediation (Criterion C4)*: An AI environment assisted in conducting code audits that identified the four codebase vulnerabilities (unencoded error string reflection, wildcard SQL LIKE dumping, pipe claim delimiter injection, and unbounded work factors) and assisted in formulating defensive patches.
  4. *Test Suite Generation & Verification (Criterion C5)*: An AI environment assisted in generating unit test assertions across [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs), [`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs), and [`Tests/TestVulnerabilityRemediation.cs`](../../Tests/TestVulnerabilityRemediation.cs), culminating in an automated 28-test suite verifying the cumulative security posture of SafeVault.
- **Build & Test Verification**: All SafeVault code compiles with `0` warnings and `0` errors under the `.NET 8.0` SDK and passes all 28 automated test assertions (`[M]`).
