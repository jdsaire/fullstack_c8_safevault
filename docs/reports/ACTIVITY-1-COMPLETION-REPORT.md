# Activity 1 Completion Report · SafeVault Capstone

| Document Metadata | Value |
|---|---|
| **Activity ID** | Course 8 Capstone · Activity 1 (C8-ACT1) |
| **Title** | Input Validation, Parameterized Queries & Multipage Architecture |
| **Author** | Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`) |
| **Specialization** | Microsoft Full Stack Developer Specialization |
| **Course** | Course 8: Security and Authentication |
| **Status** | **COMPLETE & MERGED TO MAIN** |
| **Pull Requests Landed** | [#1](https://github.com/jdsaire/fullstack_c8_safevault/pull/1), [#2](https://github.com/jdsaire/fullstack_c8_safevault/pull/2), [#3](https://github.com/jdsaire/fullstack_c8_safevault/pull/3) |
| **Live Deployment** | [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/) |
| **Date** | November 10–11, 2026 |

---

## 1. Executive Summary

Activity 1 of the SafeVault Capstone establishes the defense-in-depth secure coding baseline for the entire application. The primary objective was to eliminate the two most pervasive OWASP web vulnerabilities—**SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**—across client and server boundaries, substantiated by an automated NUnit test fixture and an interactive, WCAG 2.1 AAA accessible multipage demonstration platform.

Over three sequential engineering cycles (PR #1, PR #2, and PR #3), SafeVault progressed from a raw project scaffolding into a robust, modular multipage architecture with zero broken endpoints, dual-mode execution (supporting both local ASP.NET Core environments and static GitHub Pages hosting), and dedicated, quarantined telemetry consoles.

### Milestone Deliverables Achieved
- **C# / ASP.NET Core Defensive Boundary**: Built `src/SafeVault/Services/InputValidator.cs` and `src/SafeVault/Data/UserRepository.cs` leveraging RFC 5322 regex checks, HTML entity encoding (`WebUtility.HtmlEncode`), and explicit parameterized queries (`SqliteParameter`).
- **NUnit Vulnerability Test Suite**: Built `Tests/TestInputValidation.cs` containing 8 automated unit tests simulating tautologies, stacked table drops, inline comments, malicious script injection tags, and input length boundaries. Achieved 100% pass rate.
- **Multipage Demonstration Architecture**: Built a 5-page modular web application (`index.html`, `cycle1-intake.html`, `cycle2-sqli.html`, `cycle3-xss.html`, `cycle4-tests.html`, and `webform.html`) with shared stylesheets (`css/styles.css`) and security runtime engine (`js/safevault.js`).
- **Quarantined Telemetry & Execution Inspector**: Implemented collapsible telemetry inspectors across all cycle pages with Show/Hide, Copy Code, and Reset Log actions, preventing DOM leakage or orphaned execution traces.
- **Accessibility & Compliance**: Enforced WCAG 2.1 AAA contrast ratios (>= 12:1), >= 16px body/input typography, and >= 44px touch targets across dark slate interfaces.

---

## 2. Specialization Rubric & Criteria Alignment

| Rubric Criterion | Capstone Requirement | SafeVault Implementation Reference | Status |
|---|---|---|---|
| **Criterion C1** | Project scaffolding & solution structure | `SafeVault.sln`, `src/SafeVault/SafeVault.csproj` (.NET 8 Minimal API), `Tests/Tests.csproj` (NUnit 3.14). | **Met (100%)** |
| **Criterion C2** | Web form input validation & dual-stage sanitization | `cycle1-intake.html`, `webform.html`, and `InputValidator.cs`: Regex `^[a-zA-Z0-9_.-]+$`, boundary 3–50 chars, `WebUtility.HtmlEncode`. | **Met (100%)** |
| **Criterion C3** | Database schema & parameterized SQL queries | `database.sql` (`Users` schema), `UserRepository.cs`: Parameterized queries with `SqliteParameter` binding literal text values. | **Met (100%)** |
| **Criterion C4** | Automated vulnerability testing (SQLi & XSS) | `Tests/TestInputValidation.cs`: `TestForSQLInjection()` (tautologies, stacked drops), `TestForXSS()` (script tags, event handlers). | **Met (100%)** |
| **Criterion C5** | Test execution reporting & telemetry | `dotnet test` console logger (detailed), live telemetry in Cycle 4 interface with pass/fail duration metrics. | **Met (100%)** |
| **Criterion C6** | Written summary with AI disclosure | Documented in `README.md` under `## AI Assistance Disclosure` using generic, non-vendor terminology in compliance with AG-Q5. | **Met (100%)** |

---

## 3. Chronological Evolution & Iteration History

### Phase 1: Baseline Architecture & Scaffolding (PR #1)
- **Objective**: Establish the foundation of SafeVault, secure the repository, implement defensive controls, write the automated test fixture, and deploy an initial interactive demonstration.
- **Actions Taken**:
  - Initialized git tracking with `.gitignore` excluding build artifacts, binaries, and local SQLite databases.
  - Created .NET 8 solution (`SafeVault.sln`) with ASP.NET Core project (`src/SafeVault`) and NUnit project (`Tests`).
  - Implemented `InputValidator.cs` to enforce structural validation and entity escaping.
  - Implemented `UserRepository.cs` using `Microsoft.Data.Sqlite` with parameterized commands.
  - Formulated 8 unit tests in `TestInputValidation.cs` validating SQLi tautologies and script vectors.
  - Designed initial dark-themed security dashboard (`index.html` & `webform.html`).
  - Configured GitHub Pages deployment on branch `activity-1-input-validation`.
- **Landed Commit**: `4654021 Merge pull request #1 from jdsaire/activity-1-input-validation`

### Phase 2: WCAG 2.1 AAA Accessibility & Guided Missions (PR #2)
- **Driver**: Principal review identified that the initial dashboard was overly dense, typography was too small (0.7–0.8rem), lacked WCAG accessibility, and did not prompt visitors on what specific tasks to execute.
- **Actions Taken**:
  - Overhauled typography: Raised base font to 16px (`1rem`), card titles to 18px (`1.125rem`), code blocks to 14.5px (`0.9rem`), and labels to 15.5px.
  - Elevated contrast ratios: Paired `#f8fafc` text with `#1e293b` backgrounds, exceeding WCAG 2.1 AAA minimums (>= 12:1).
  - Designed interactive "Guided Task Cycles" banner featuring 4 explicit execution missions: Valid Intake, SQLi Defense, XSS Mitigation, and Automated Suite.
  - Configured GitHub Pages deployment source to track `main` branch directly.
- **Landed Commit**: `3a87c50 Merge pull request #2 from jdsaire/activity-1-ui-refinement`

### Phase 3: Root Cause Analysis, Multipage Architecture & Telemetry Quarantine (PR #3)
- **Driver**: Visual inspection of the live deployment revealed that mission buttons and tab selectors were non-responsive, redundant tabs cluttered the page, and raw JavaScript code was visibly rendered beneath the footer (`image.png` & `image_2.png`).
- **Forensic Investigation**:
  - Identified an unescaped literal closing script tag (`</script>`) inside an inline JavaScript string preset (`loadPreset("<script>alert('XSS')</script>", ...)`).
  - In standard HTML parsing, any literal `</script>` string inside an inline `<script>` element terminates script execution immediately, dumping all subsequent JavaScript into the DOM as plain text and preventing event listeners from attaching.
- **Architectural Resolution**:
  - **Decoupled Single Page into Modular Multipage Architecture**: Retired the sky-blue tab navigation and established 5 dedicated, full-screen execution pages (`index.html`, `cycle1-intake.html`, `cycle2-sqli.html`, `cycle3-xss.html`, `cycle4-tests.html`, `webform.html`).
  - **Extracted Shared Engine**: Created `css/styles.css` for system-wide styling and `js/safevault.js` for the security runtime. External JavaScript files are parsed by the JS engine directly, completely immune to HTML parser script termination.
  - **Quarantined Telemetry Inspector**: Built a standardized, collapsible telemetry console with Show/Hide, Copy Code, and Reset Log controls.
  - **Scope Boundary Enforcement**: Formally delineated the boundary between Activity 1 (validation & parameterization) and Activity 2 (authentication & RBAC).
- **Landed Commit**: `eb99ab5 Merge pull request #3 from jdsaire/activity-1-multipage-debug`

---

## 4. Technical Debugging Deep Dive

### Defect 1: Inline `<script>` Tag Parser Premature Termination
- **Symptom**: In `image_2.png`, raw JavaScript was rendered in the viewport below the footer (`", "xss_probe@test.local"); showNotification('Mission 3...`);`), and all interactive buttons failed to respond.
- **Root Cause**:
  ```html
  <!-- Flawed Inline Script -->
  <script>
      function runMission3() {
          loadPreset("<script>alert('XSS')</script>", "xss_probe@test.local");
          // ...
      }
  </script>
  ```
  The HTML parser does not tokenize JavaScript string literals. Encountering `</script>` at index 41 triggered an immediate closing tag event, splitting the script block in half.
- **Fix Applied**:
  1. Extracted all JavaScript logic to external file [`js/safevault.js`](../../js/safevault.js).
  2. Replaced inline literal string references with safe escaped expressions:
     ```javascript
     const scriptPayload = '<script>' + 'alert(1)' + '<\/script>';
     ```
  3. Audited rendered DOM via headless Chrome to guarantee zero code leakage outside container elements.

### Defect 2: SQLite In-Memory Database Discard on Connection Close
- **Symptom**: NUnit tests in `Tests/TestInputValidation.cs` failed with `SQLite Error 1: 'no such table: Users'`.
- **Root Cause**: SQLite in-memory databases (`Data Source=:memory:`) are ephemeral and destroyed the instant their `SqliteConnection` is closed. The initial `UserRepository` implementation opened and closed connections per method call.
- **Fix Applied**:
  Refactored `UserRepository` to maintain an open `SqliteConnection` for the lifecycle of the instance and implement `IDisposable`:
  ```csharp
  public class UserRepository : IDisposable
  {
      private readonly SqliteConnection _connection;
      public UserRepository(string connectionString)
      {
          _connection = new SqliteConnection(connectionString);
          _connection.Open();
          InitializeDatabase();
      }
      public void Dispose() => _connection?.Dispose();
  }
  ```
  Updated `TestInputValidation.cs` with an `[TearDown]` hook to dispose repository connections cleanly after each test.

### Defect 3: Dual-Mode Execution on Static GitHub Pages vs ASP.NET Core
- **Symptom**: Submitting forms on GitHub Pages returned HTTP 405/404 because GitHub Pages serves static files and does not execute ASP.NET Core Kestrel backends.
- **Root Cause**: The client-side form attempted a hard `fetch('/submit')`.
- **Fix Applied**:
  Implemented an intelligent dual-mode engine in `js/safevault.js`. It attempts to call the local ASP.NET Core API first; if running on a static host (GitHub Pages or local file protocol), it seamlessly falls back to an in-memory SQLite simulation engine with pre-seeded records:
  ```javascript
  let backendSucceeded = false;
  try {
      const res = await fetch('/submit', { method: 'POST', body: ... });
      if (res.ok) backendSucceeded = true;
  } catch (e) {
      backendSucceeded = false; // Fallback to simulated repository
  }
  ```

---

## 5. Security Telemetry & Test Suite Audit

### NUnit Automated Test Results (`Tests/TestInputValidation.cs`)
```
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

### Attack Vector Defense Coverage Matrix

| Test Method | Simulated Attack Vector | Target Surface | Defensive Mechanism | Outcome |
|---|---|---|---|---|
| `TestForSQLInjection()` | `admin' OR '1'='1` (Tautology) | `UserRepository.GetUserByUsername()` | Parameter bound as literal string; 0 rows returned | **Blocked** |
| `TestForSQLInjection()` | `test'; DROP TABLE Users; --` (Stacked Drop) | `UserRepository.GetUserByUsername()` | Semicolon treated as string text; table 100% intact | **Blocked** |
| `TestForSQLInjection()` | `' OR 1=1 --` (Comment Evasion) | `UserRepository.GetUserByUsername()` | Hyphens treated as literal string; 0 rows returned | **Blocked** |
| `TestForXSS()` | `<script>alert('XSS')</script>` | `InputValidator.Sanitize()` | Encoded to `&lt;script&gt;alert('XSS')&lt;/script&gt;` | **Neutralized** |
| `TestForXSS()` | `<img src=x onerror=alert('XSS')>` | `InputValidator.Sanitize()` | Angle brackets and `on*` attributes sanitized | **Neutralized** |
| `TestForXSS()` | `javascript:alert(1)` | `InputValidator.Validate()` | Regex `^[a-zA-Z0-9_.-]+$` rejects colons and protocols | **Rejected** |
| `TestInvalidInput()` | Empty string (`""`) | `InputValidator.Validate()` | Required rule triggers "Username is required." | **Rejected** |
| `TestInvalidInput()` | Short string (`"ab"`) | `InputValidator.Validate()` | Boundary rule triggers length between 3 and 50 | **Rejected** |
| `TestInvalidInput()` | Spaces (`"invalid user name"`) | `InputValidator.Validate()` | Character set rule triggers invalid characters error | **Rejected** |
| `TestInvalidInput()` | Malformed email (`"not-an-email"`) | `InputValidator.Validate()` | RFC 5322 regex triggers invalid email format | **Rejected** |
| `TestValidInput()` | `john_doe`, `john@example.com` | `InputValidator.Validate()` | Fully compliant credentials pass with 0 errors | **Accepted** |

---

## 6. Multipage Component Architecture

```
fullstack_c8_safevault/
├── .gitignore                      # Git exclusion rules (binaries, databases, obj)
├── .nojekyll                       # GitHub Pages bypass for Jekyll processing
├── README.md                       # Repository overview, architecture & AI disclosure
├── SafeVault.sln                   # .NET 8 solution manifest
├── database.sql                    # Relational schema (Users table definition)
├── docs/
│   └── reports/
│       ├── README.md               # Completion reports governance & directory index
│       └── ACTIVITY-1-COMPLETION-REPORT.md # This document
├── index.html                      # Mission Hub (Overview, boundaries & navigation)
├── cycle1-intake.html              # Cycle 1: Legitimate intake form & live database
├── cycle2-sqli.html                # Cycle 2: SQLi attack console & parameter inspector
├── cycle3-xss.html                 # Cycle 3: XSS dual-stage sanitization console
├── cycle4-tests.html               # Cycle 4: Automated NUnit test suite runner
├── webform.html                    # Standalone form page satisfying rubric file name
├── css/
│   └── styles.css                  # Shared WCAG 2.1 AAA accessible dark theme styles
├── js/
│   └── safevault.js                # Shared client-side security & telemetry engine
├── src/
│   └── SafeVault/
│       ├── Program.cs              # ASP.NET Core Minimal API endpoints (/submit)
│       ├── SafeVault.csproj        # Application project file (net8.0)
│       ├── Data/
│       │   └── UserRepository.cs   # SQLite data access with parameterized commands
│       ├── Models/
│       │   └── UserSubmission.cs   # Data transfer model
│       └── Services/
│           └── InputValidator.cs   # Defensive validation and HTML entity encoder
└── Tests/
    ├── Tests.csproj                # NUnit test project (net8.0, Microsoft.NET.Test.Sdk)
    └── TestInputValidation.cs      # 8 automated security unit test cases
```

---

## 7. Scope Boundaries: Activity 1 vs Activity 2

To maintain engineering discipline and prevent feature creep across course activities, the boundary between Activity 1 and Activity 2 is strictly enforced:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       ACTIVITY 1 SCOPE (COMPLETED)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔ Client-side HTML5 constraint validation and character length boundaries  │
│  ✔ Server-side regular expression structural verification (RFC 5322)        │
│  ✔ Dual-stage sanitization: tag stripping & WebUtility.HtmlEncode           │
│  ✔ SQLite parameterized queries (SqliteParameter literal string bindings)   │
│  ✔ Automated NUnit test suite for SQL injection and XSS attack vectors      │
│  ✔ Multipage demonstration interface & quarantined telemetry consoles       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼ [ISOLATION BOUNDARY]
┌─────────────────────────────────────────────────────────────────────────────┐
│                     ACTIVITY 2 SCOPE (PENDING ARGON RUN)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✖ User authentication and credential management (login endpoints)          │
│  ✖ Cryptographic password hashing with salts (Argon2 / PBKDF2 / bcrypt)     │
│  ✖ Authentication tokens, cookies, or JWT session middleware                │
│  ✖ Role-Based Access Control (RBAC) (roles: Admin, User, Auditor)           │
│  ✖ Route-level authorization policies and permission gates                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

> **Boundary Confirmation**: Activity 1 contains zero authentication or RBAC logic. All credential-handling mechanisms are preserved intact for execution under Activity 2.

---

## 8. Artifact & Verification Audit Ledger

| Artifact Category | Identifier / Target | Location / Hash | Verification Status |
|---|---|---|---|
| **Git Baseline** | Initial repository commit | `9414f6b` on `main` | Verified |
| **Pull Request #1** | Activity 1 Scaffolding & Defense | Merged at `4654021` | Merged by JD |
| **Pull Request #2** | WCAG 2.1 AAA & Guided Missions | Merged at `3a87c50` | Merged by JD |
| **Pull Request #3** | Multipage Architecture & Debugging | Merged at `eb99ab5` | Merged by JD |
| **Active Deployment** | GitHub Pages Live Demo | `https://jdsaire.github.io/fullstack_c8_safevault/` | HTTP 200 OK |
| **Visual Artifact** | Mission Hub Screenshot | `preview_hub.png` | Captured & Verified |
| **Visual Artifact** | Cycle 1 Intake Screenshot | `preview_cycle1.png` | Captured & Verified |
| **Visual Artifact** | Cycle 2 SQLi Screenshot | `preview_cycle2.png` | Captured & Verified |
| **Visual Artifact** | Cycle 3 XSS Screenshot | `preview_cycle3.png` | Captured & Verified |
| **Visual Artifact** | Cycle 4 Tests Screenshot | `preview_cycle4.png` | Captured & Verified |
| **Drive Outbox** | Activity 1 Archive Folder | ID: `1ImA5OINvJsBStkFxIXsKV5pZBnGk8lEP` | Synchronized |
| **Drive Outbox** | Close-out Run Record | ID: `18nFzAypJaPUwsXg5y1uiYzyEWkTgcxg9` | Updated |
| **Drive Outbox** | Final Inspection Digest | ID: `19EcOLqgVf8q-JRiYyW-VxfPGan8tOkxm` | Updated |
| **Drive Outbox** | Multipage Execution Plan | ID: `1nVsxOd5PLp25JoRZUxHfGuEikqxOFQQx` | Uploaded |

---

## 9. Author & Compliance Attestation

- **Sole Author**: Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`)
- **Attribution Policy**: Zero banned AI terminology present across all repository commits, pull request descriptions, file comments, or documentation.
- **AI Disclosure Compliance**: Carve-out AG-Q5 adhered to strictly within `README.md` under generic terminology (`"an AI environment"`, `"the AI environment"`, `"AI assistance"`).
- **Tooling Execution**: All builds compiled with 0 warnings and 0 errors under .NET 8.0 SDK.
