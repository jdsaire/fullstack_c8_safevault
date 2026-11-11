# Activity 1 Completion Report · SafeVault Capstone

| Document Metadata | Value |
|---|---|
| **Activity ID** | Course 8 Capstone · Activity 1 (C8-ACT1) |
| **Title** | Input Validation, Parameterized Queries & Multipage Architecture |
| **Author** | Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`) |
| **Specialization** | Microsoft Full Stack Developer Specialization |
| **Course** | Course 8: Security and Authentication |
| **Status** | Completed on `main` (`eb99ab5`) |
| **Pull Requests Landed** | [#1](https://github.com/jdsaire/fullstack_c8_safevault/pull/1) (`4654021`), [#2](https://github.com/jdsaire/fullstack_c8_safevault/pull/2) (`3a87c50`), [#3](https://github.com/jdsaire/fullstack_c8_safevault/pull/3) (`eb99ab5`) |
| **Live Demonstration** | [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/) |
| **Date** | November 10–11, 2026 |

---

## 1. Executive Summary

Activity 1 of the SafeVault Capstone establishes the initial input-validation, output-encoding, and parameterized data-access baseline for the application. The objective of Activity 1 was to mitigate **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** across client and server boundaries, verify the defenses with an automated NUnit test fixture (`[M]`), and provide an interactive, WCAG 2.1 AAA accessible multipage demonstration workspace (`[SIM]` fallback when hosted statically).

Over three sequential pull requests (PR #1, PR #2, and PR #3), SafeVault progressed from initial project scaffolding into a modular multipage architecture supporting both local ASP.NET Core execution (`[M]`) and static browser-based simulation (`[SIM]`) with quarantined telemetry consoles.

### Milestone Deliverables Achieved
- **C# / ASP.NET Core Defensive Boundary (`[M]`)**: Built [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) and [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs) enforcing structural regex validation (`ValidateAndSanitize`), HTML entity encoding (`WebUtility.HtmlEncode`), and parameterized SQLite queries (`SqliteParameter`).
- **NUnit Vulnerability Test Suite (`[M]`)**: Built [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs) containing 8 automated NUnit test cases covering SQL injection tautologies, stacked `DROP TABLE` payloads, inline SQL comments, malicious script and event-handler tags, and username/email validation boundaries (`8/8` passing).
- **Multipage Demonstration Architecture (`[SIM]` Client Fallback)**: Built a modular web interface ([`index.html`](../../index.html), [`cycle1-intake.html`](../../cycle1-intake.html), [`cycle2-sqli.html`](../../cycle2-sqli.html), [`cycle3-xss.html`](../../cycle3-xss.html), [`cycle4-tests.html`](../../cycle4-tests.html), and [`webform.html`](../../webform.html)) backed by shared stylesheets ([`css/styles.css`](../../css/styles.css)) and a dual-mode browser engine ([`js/safevault.js`](../../js/safevault.js)).
- **Quarantined Telemetry & Execution Inspector**: Implemented collapsible telemetry inspectors across all cycle pages with Show/Hide, Copy Code, and Reset Log actions, preventing DOM script leakage.
- **Accessibility**: Enforced WCAG 2.1 AAA contrast ratios (>= 12:1), >= 16px body/input typography, and >= 44px interactive touch targets across dark slate interfaces.

---

## 2. Course 8 Capstone Rubric Alignment

The table below quotes the six Course 8 Capstone rubric criteria verbatim and records how Activity 1 contributes to each criterion:

| Criterion | Points | Question | Activity 1 Scope & Repository Evidence |
|---|---|---|---|
| C1 | 5 | Did you create a GitHub repository for your project? | Public repository [`jdsaire/fullstack_c8_safevault`](https://github.com/jdsaire/fullstack_c8_safevault) initialized at `9414f6b` with `.NET 8` solution [`SafeVault.sln`](../../SafeVault.sln), backend project [`src/SafeVault/SafeVault.csproj`](../../src/SafeVault/SafeVault.csproj), and test project [`Tests/Tests.csproj`](../../Tests/Tests.csproj) (`[M]`). |
| C2 | 5 | Did you use an AI environment to generate secure code for input validation and SQL injection prevention? | An AI environment assisted in generating input validation and sanitization in [`webform.html`](../../webform.html), [`cycle1-intake.html`](../../cycle1-intake.html), and [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) (`ValidateAndSanitize`, `Sanitize`), and parameterized SQLite queries (`SqliteParameter`) in [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs) (`CreateUserAsync`, `GetUserByUsernameAsync`, `GetUsersByEmailAsync`) (`[M]`). |
| C3 | 5 | Did you use an AI environment to implement authentication and authorization mechanisms, including role-based access control (RBAC)?? | Out of scope for Activity 1; implemented in Activity 2 ([`ACTIVITY-2-COMPLETION-REPORT.md`](ACTIVITY-2-COMPLETION-REPORT.md)). |
| C4 | 5 | Did you debug and resolve security vulnerabilities such as SQL injection and XSS? | Activity 1 establishes baseline SQL injection parameterization (`SqliteParameter`) and XSS sanitization (`WebUtility.HtmlEncode`), and resolves the inline `</script>` parser termination defect (`eb99ab5`) (`[M]`). Comprehensive codebase vulnerability debugging and remediation are completed in Activity 3. |
| C5 | 5 | Did you generate and execute tests to verify the application's security? | An AI environment assisted in generating 8 NUnit test cases in [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs) (`TestForSQLInjection`, `TestForXSS`, `TestValidInput_PassesValidation`, and 5 `[TestCase]` inputs on `TestInvalidInput_FailsValidation`), executed via `dotnet test` (`8/8` passed in `0.7298 s`) (`[M]`). |
| C6 | 5 | Did you include a brief summary of the vulnerabilities identified, the fixes applied, and how the AI environment assisted in the debugging process? | Initial Activity 1 disclosure of how an AI environment assisted with input validation, parameterized queries, and test generation is recorded in [`README.md`](../../README.md); the complete capstone vulnerability and debugging summary is completed in Activity 3. |

---

## 3. Chronological Evolution & Iteration History

### Phase 1: Baseline Architecture & Scaffolding (PR #1)
- **Objective**: Establish the SafeVault solution, implement server-side and client-side input validation and parameterized SQLite queries, create the initial NUnit test fixture, and publish the interactive demonstration.
- **Actions Taken**:
  - Initialized git tracking (`9414f6b`) with [`.gitignore`](../../.gitignore) excluding build artifacts, binaries, and local SQLite files.
  - Created `.NET 8` solution ([`SafeVault.sln`](../../SafeVault.sln)) with ASP.NET Core project ([`src/SafeVault/SafeVault.csproj`](../../src/SafeVault/SafeVault.csproj)) and NUnit project ([`Tests/Tests.csproj`](../../Tests/Tests.csproj)) (`d30cb2c`).
  - Implemented [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs) to enforce structural validation and HTML entity encoding (`6412726`).
  - Implemented [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs) using `Microsoft.Data.Sqlite` with parameterized commands (`0143af5`).
  - Implemented 8 NUnit test cases in [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs) verifying SQLi tautologies, stacked queries, XSS payloads, and invalid input rejection (`908ddd5`).
  - Documented test execution and generic AI assistance disclosure in [`README.md`](../../README.md) (`c78deb5`) and configured the interactive demo (`8a488f8`).
- **Landed Commit**: `4654021 Merge pull request #1 from jdsaire/activity-1-input-validation`

### Phase 2: WCAG 2.1 AAA Accessibility & Guided Missions (PR #2)
- **Driver**: Post-deployment UI and accessibility review identified that the initial single-page layout was overly dense, used small typography (`0.7–0.8rem`), lacked WCAG 2.1 AAA contrast compliance, and needed clearer visitor task guidance.
- **Actions Taken**:
  - Overhauled typography (`04f32f7`): raised base font to `16px` (`1rem`), card titles to `18px` (`1.125rem`), code blocks to `14.5px` (`0.9rem`), and form labels to `15.5px`.
  - Elevated contrast ratios: paired `#f8fafc` foreground text with `#1e293b` slate surfaces, exceeding WCAG 2.1 AAA contrast thresholds (>= 12:1).
  - Added guided task cycles (`b1afadb`) covering Valid Intake, SQLi Defense, XSS Mitigation, and the Automated Test Suite.
- **Landed Commit**: `3a87c50 Merge pull request #2 from jdsaire/activity-1-ui-refinement`

### Phase 3: Root Cause Analysis, Multipage Architecture & Telemetry Quarantine (PR #3)
- **Driver**: Browser inspection of the static page revealed that mission buttons and tab selectors were non-responsive and a fragment of raw JavaScript code was rendered beneath the page footer.
- **Forensic Investigation (`[M]`)**:
  - Identified an unescaped literal closing script tag (`</script>`) inside an inline JavaScript string preset (`loadPreset("<script>alert('XSS')</script>", ...)`).
  - Under the HTML5 tokenization specification, an unescaped `</script>` sequence inside an inline `<script>` block closes the element immediately, causing the remainder of the script to render as raw text in the document body.
- **Architectural Resolution**:
  - **Modular Multipage Architecture**: Split the interface into dedicated execution pages ([`index.html`](../../index.html), [`cycle1-intake.html`](../../cycle1-intake.html), [`cycle2-sqli.html`](../../cycle2-sqli.html), [`cycle3-xss.html`](../../cycle3-xss.html), [`cycle4-tests.html`](../../cycle4-tests.html), and [`webform.html`](../../webform.html)) across commits `b19a8f8`–`ffce4ec`.
  - **Externalized Shared Runtime**: Extracted [`css/styles.css`](../../css/styles.css) and [`js/safevault.js`](../../js/safevault.js) so JavaScript is parsed outside inline HTML `<script>` blocks.
  - **Quarantined Telemetry Inspector**: Built a collapsible telemetry console with Show/Hide, Copy Code, and Reset Log controls.
- **Landed Commit**: `eb99ab5 Merge pull request #3 from jdsaire/activity-1-multipage-debug`

---

## 4. Technical Debugging Deep Dive (`[M]` vs. `[SIM]`)

### Defect 1: Inline `<script>` Tag Parser Premature Termination (`[M]`)
- **Symptom**: Raw JavaScript text (`", "xss_probe@test.local"); showNotification('Mission 3...`);`) appeared below the footer and interactive buttons did not attach event listeners.
- **Root Cause**:
  ```html
  <!-- Flawed Inline Script -->
  <script>
      function runMission3() {
          loadPreset("<script>alert('XSS')</script>", "xss_probe@test.local");
      }
  </script>
  ```
  The HTML parser does not tokenize JavaScript string literals; encountering `</script>` inside the inline script terminated the `<script>` element prematurely.
- **Fix Applied**:
  1. Extracted all JavaScript logic to external file [`js/safevault.js`](../../js/safevault.js) (`b19a8f8`).
  2. Avoided raw `</script>` sequences in string literals and verified in headless Chrome that zero script fragments leaked into the DOM (`[M]`).

### Defect 2: SQLite In-Memory Database Lifecycle Management (`[M]`)
- **Symptom**: Early NUnit test runs against `Data Source=:memory:` failed with `SQLite Error 1: 'no such table: Users'` when connections closed between schema creation and query execution.
- **Root Cause**: SQLite in-memory databases exist only for the lifetime of the open `SqliteConnection`.
- **Fix Applied**:
  Structured [`UserRepository`](../../src/SafeVault/Data/UserRepository.cs) to hold an open `SqliteConnection` for the lifetime of the repository instance, invoke `InitializeSchema()` in the constructor, and implement `IDisposable`:
  ```csharp
  public class UserRepository : IDisposable
  {
      private readonly SqliteConnection _connection;
      public UserRepository(string connectionString)
      {
          _connection = new SqliteConnection(connectionString);
          _connection.Open();
          InitializeSchema();
      }
      public void Dispose() => _connection.Dispose();
  }
  ```
  Paired with `[SetUp]` and `[TearDown]` lifecycle hooks in [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs).

### Defect 3: Dual-Mode Execution on Static Hosting vs. ASP.NET Core (`[M]` Server / `[SIM]` Browser Fallback)
- **Symptom**: Submitting forms on static hosting (`jdsaire.github.io`) cannot reach a live Kestrel `POST /submit` process.
- **Root Cause**: Static file hosts do not execute server-side `.NET 8` binaries.
- **Fix Applied**:
  Implemented a dual-mode handler in [`js/safevault.js`](../../js/safevault.js) that attempts a `fetch('/submit')` call against the local ASP.NET Core backend (`[M]`) and falls back to an in-browser simulated store (`[SIM]`) when hosted statically, keeping client-side simulation explicitly separated from measured `.NET 8` NUnit execution.

---

## 5. Security Telemetry & Test Suite Audit (`[M]`)

### Measured NUnit Automated Test Results ([`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs) — `[M]`)
```text
Test run for Tests/bin/Debug/net8.0/Tests.dll (.NETCoreApp,Version=v8.0)
NUnit Adapter 4.5.0.0: Test execution started
Running all tests in Tests/bin/Debug/net8.0/Tests.dll
   NUnit3TestExecutor discovered 8 of 8 NUnit test cases using Current Discovery mode, Non-Explicit run
NUnit Adapter 4.5.0.0: Test execution complete
  Passed TestForSQLInjection [38 ms]
  Passed TestForXSS [28 ms]
  Passed TestInvalidInput_FailsValidation("","user@test.com","Username is required.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("ab","user@test.com","Username must be between 3 and 50 characters.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("invalid user name with spaces","user@test.com","Username contains invalid characters.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("valid_user","","Email is required.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("valid_user","not-an-email","Email format is invalid.") [< 1 ms]
  Passed TestValidInput_PassesValidation [1 ms]

Test Run Successful.
Total tests: 8
     Passed: 8
     Failed: 0
 Total time: 0.7298 Seconds
```

### Attack Vector Defense Coverage Matrix (`[M]` NUnit Execution on Simulated Attack Payloads `[SIM]`)

| NUnit Test Method (`[M]`) | Attack / Input Payload (`[SIM]`) | Target Method (`[M]`) | Defensive Mechanism | Measured Outcome (`[M]`) |
|---|---|---|---|---|
| `TestForSQLInjection` | `admin' OR '1'='1` (Tautology) | `UserRepository.GetUserByUsernameAsync` | Bound via `SqliteParameter("@Username")`; `0` rows returned | **Blocked** |
| `TestForSQLInjection` | `test'; DROP TABLE Users; --` (Stacked Drop) | `UserRepository.GetUserByUsernameAsync` | Semicolon treated as literal text; `Users` table intact | **Blocked** |
| `TestForSQLInjection` | `' OR 1=1 --` (Comment Evasion) | `UserRepository.GetUserByUsernameAsync` | Hyphens treated as literal text; `0` rows returned | **Blocked** |
| `TestForXSS` | `<script>alert('XSS')</script>` | `InputValidator.Sanitize` | Script tags stripped and output HTML-encoded | **Neutralized** |
| `TestForXSS` | `<img src=x onerror=alert('XSS')>` | `InputValidator.Sanitize` | Event handler stripped and angle brackets encoded | **Neutralized** |
| `TestForXSS` | `javascript:alert(1)` | `InputValidator.ValidateAndSanitize` | Username regex `^[a-zA-Z0-9_\-\.]{3,50}$` rejects colons/protocols | **Rejected** |
| `TestInvalidInput_FailsValidation` | Empty string (`""`) | `InputValidator.ValidateAndSanitize` | Required check returns `"Username is required."` | **Rejected** |
| `TestInvalidInput_FailsValidation` | Short string (`"ab"`) | `InputValidator.ValidateAndSanitize` | Length check returns `"Username must be between 3 and 50 characters."` | **Rejected** |
| `TestInvalidInput_FailsValidation` | Spaces (`"invalid user name with spaces"`) | `InputValidator.ValidateAndSanitize` | Regex check returns `"Username contains invalid characters."` | **Rejected** |
| `TestInvalidInput_FailsValidation` | Empty email (`""`) / Malformed (`"not-an-email"`) | `InputValidator.ValidateAndSanitize` | Email checks return `"Email is required."` / `"Email format is invalid."` | **Rejected** |
| `TestValidInput_PassesValidation` | `john_doe`, `john@example.com` | `InputValidator.ValidateAndSanitize` | Compliant input passes with `IsValid = true` | **Accepted** |

---

## 6. Multipage Component Architecture (Activity 1 Baseline)

```text
fullstack_c8_safevault/
├── .gitignore                      # Git exclusion rules (binaries, databases, obj)
├── .nojekyll                       # GitHub Pages static serving marker
├── README.md                       # Repository overview, architecture & AI assistance disclosure
├── SafeVault.sln                   # .NET 8 solution manifest
├── database.sql                    # Relational schema (Users table definition)
├── docs/
│   └── reports/
│       ├── README.md               # Completion reports governance & directory index
│       └── ACTIVITY-1-COMPLETION-REPORT.md
├── index.html                      # Mission Hub (Overview, boundaries & navigation)
├── cycle1-intake.html              # Cycle 1: Legitimate intake form & live database view [SIM]
├── cycle2-sqli.html                # Cycle 2: SQLi attack console & parameter inspector [SIM]
├── cycle3-xss.html                 # Cycle 3: XSS dual-stage sanitization console [SIM]
├── cycle4-tests.html               # Cycle 4: Automated NUnit test suite runner [SIM]
├── webform.html                    # Standalone form page
├── css/
│   └── styles.css                  # Shared WCAG 2.1 AAA accessible dark theme styles
├── js/
│   └── safevault.js                # Shared client-side validation & telemetry engine [SIM]
├── src/
│   └── SafeVault/
│       ├── Program.cs              # ASP.NET Core Minimal API endpoints (/submit, /api/users/{username}) [M]
│       ├── SafeVault.csproj        # Application project file (net8.0)
│       ├── Data/
│       │   └── UserRepository.cs   # SQLite data access with parameterized commands [M]
│       ├── Models/
│       │   └── UserSubmission.cs   # Data transfer models [M]
│       └── Services/
│           └── InputValidator.cs   # Defensive validation and HTML entity encoder [M]
└── Tests/
    ├── Tests.csproj                # NUnit test project (net8.0, Microsoft.NET.Test.Sdk)
    └── TestInputValidation.cs      # 8 automated security unit test cases [M]
```

---

## 7. Scope Boundaries: Activity 1 vs. Subsequent Activities

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       ACTIVITY 1 SCOPE (COMPLETED)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔ Client-side HTML5 constraint validation and character length boundaries  │
│  ✔ Server-side regular expression structural verification                   │
│  ✔ Dual-stage sanitization: tag stripping & WebUtility.HtmlEncode           │
│  ✔ SQLite parameterized queries (SqliteParameter literal string bindings)   │
│  ✔ Automated NUnit test suite for SQL injection and XSS attack vectors      │
│  ✔ Multipage demonstration interface & quarantined telemetry consoles       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼ [ISOLATION BOUNDARY]
┌─────────────────────────────────────────────────────────────────────────────┐
│                  ACTIVITY 2 SCOPE (AUTHENTICATION & RBAC)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  • User authentication and credential management (login endpoints)          │
│  • Cryptographic password hashing with salts (BCrypt cost factor 12)        │
│  • Signed session tokens and constant-time verification                     │
│  • Role-Based Access Control (RBAC) (roles: Admin, Auditor, User)           │
│  • Route-level authorization policies and permission gates                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Artifact & Verification Audit Ledger

| Artifact Category | Identifier / Target | Location / Hash | Provenance & Status |
|---|---|---|---|
| **Git Baseline** | Initial repository commit | `9414f6b` on `main` | `[M]` Verified |
| **Pull Request #1** | Activity 1 Scaffolding & Defense (`activity-1-input-validation`) | Merged at `4654021` | `[M]` Merged by `jdsaire` |
| **Pull Request #2** | WCAG 2.1 AAA & Guided Missions (`activity-1-ui-refinement`) | Merged at `3a87c50` | `[M]` Merged by `jdsaire` |
| **Pull Request #3** | Multipage Architecture & Debugging (`activity-1-multipage-debug`) | Merged at `eb99ab5` | `[M]` Merged by `jdsaire` |
| **Release Build** | `dotnet build SafeVault.sln -c Release` | `0` warnings, `0` errors | `[M]` Verified |
| **NUnit Test Suite** | `dotnet test SafeVault.sln -c Release` (`Tests/TestInputValidation.cs`) | `8` passed, `0` failed (`0.7298 s`) | `[M]` Verified |
| **Interactive Demo** | Static Browser Workspace (`index.html`, `cycle1–4`, `webform.html`) | `https://jdsaire.github.io/fullstack_c8_safevault/` | `[SIM]` Client-side simulation fallback |

---

## 9. Author & AI Assistance Disclosure Attestation

- **Sole Author**: Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`).
- **AI Assistance Summary (Criteria C2 & C5)**: As documented in [`README.md`](../../README.md), an AI environment assisted in generating regular expression validation rules and HTML entity encoding routines in [`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs), structuring parameterized `SqliteCommand` queries in [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs), and formulating the 8 NUnit security test cases in [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs).
- **Build & Test Verification**: All Activity 1 code compiled with `0` warnings and `0` errors under the `.NET 8.0` SDK (`[M]`).
