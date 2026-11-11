# Activity 2 Completion Report · SafeVault Capstone

| Document Metadata | Value |
|---|---|
| **Activity ID** | Course 8 Capstone · Activity 2 (C8-ACT2) |
| **Title** | Authentication & Role-Based Access Control (RBAC) |
| **Author** | Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`) |
| **Specialization** | Microsoft Full Stack Developer Specialization |
| **Course** | Course 8: Security and Authentication |
| **Status** | Completed on `main` (`feedc6a`) |
| **Pull Request Landed** | [#4](https://github.com/jdsaire/fullstack_c8_safevault/pull/4) (`feedc6a`) |
| **Live Demonstration** | [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/) |
| **Date** | November 11, 2026 |

---

## 1. Executive Summary

Activity 2 of the SafeVault Capstone extends the input-validation and parameterized-query baseline from Activity 1 with **cryptographic user authentication**, **salted BCrypt password hashing**, **HMAC-SHA256 signed session tokens**, and **Role-Based Access Control (RBAC)** across backend services (`[M]`), Minimal API endpoints (`[M]`), automated NUnit security tests (`[M]`), and two interactive multipage verification workspaces ([`cycle5-auth.html`](../../cycle5-auth.html) and [`cycle6-rbac.html`](../../cycle6-rbac.html), `[SIM]` client fallback).

All user credentials are hashed using `BCrypt.Net-Next` (`4.0.3`) with an explicit default work factor of `12` ($2^{12} = 4,096$ Blowfish key expansion rounds) and a cryptographically random 128-bit salt embedded into each 60-character `$2a$12$...` modular crypt hash (`[M]`). Authentication resists timing-based account enumeration via dummy-hash verification when a username does not exist, and route-level authorization enforces role gates (`Admin`, `Auditor`, `User`) backed by HMAC-SHA256 signed bearer tokens verified in constant time (`CryptographicOperations.FixedTimeEquals`) (`[M]`).

### Milestone Deliverables Achieved
- **Schema & Parameterized Repository Extension (`[M]`)**: Extended [`database.sql`](../../database.sql) and [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs) with `PasswordHash`, `Role` (`CHECK (Role IN ('Admin', 'Auditor', 'User'))`), `CreatedAt`, and parameterized `RegisterUserAsync`, `GetUserAccountByUsernameAsync`, `GetUserByUsernameAsync`, `UpdateUserRoleAsync`, and `GetAllUsersAsync` queries using `SqliteParameter`.
- **Cryptographic Password Hashing (`[M]`)**: Implemented `HashPassword`, `VerifyPassword`, and `InspectHashMetadata` in [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs) using `BCrypt.Net-Next` (default work factor `12`, unique 128-bit salts).
- **Constant-Time Authentication (`[M]`)**: Implemented `RegisterUserAsync` and `AuthenticateAsync` in [`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs) combining input validation (`InputValidator`), parameterized SQLite lookup, BCrypt digest verification, and dummy-hash verification to prevent user enumeration.
- **Role-Based Access Control & Token Service (`[M]`)**: Implemented policy gates (`AuthorizeAdminDashboard`, `AuthorizeRoleManagement`, `AuthorizeAuditLogs`, `AuthorizeUserVault`, `AuthorizeByRole`) and HMAC-SHA256 bearer token issuance/verification (`IssueSessionToken`, `ValidateSessionToken`) in [`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs), wired to Minimal API routes in [`src/SafeVault/Program.cs`](../../src/SafeVault/Program.cs) (`POST /api/auth/register`, `POST /api/auth/login`, `GET /api/admin/dashboard`, `POST /api/admin/users/role`, `GET /api/audit/logs`, `GET /api/vault/profile`) returning `200 OK`, `401 Unauthorized`, or `403 Forbidden`.
- **Expanded NUnit Security Test Suite (`[M]`)**: Added 10 NUnit security tests in [`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs) covering unique salt generation, password verification, invalid login rejection, non-existent user anti-enumeration, SQLi login neutralization, `Admin` / `Auditor` / `User` RBAC enforcement, and tampered token rejection (`18/18` cumulative NUnit tests passing at Activity 2 completion).
- **Multipage UI Workspaces (`[SIM]` Client Fallback)**: Added dedicated WCAG 2.1 AAA workspaces ([`cycle5-auth.html`](../../cycle5-auth.html), [`cycle6-rbac.html`](../../cycle6-rbac.html), and updated [`cycle4-tests.html`](../../cycle4-tests.html)) for BCrypt hash dissection, login attack simulation, RBAC route probing, and interactive test execution with quarantined collapsible telemetry panels.

---

## 2. Course 8 Capstone Rubric Alignment

The table below quotes the six Course 8 Capstone rubric criteria verbatim and records how Activity 2 contributes to each criterion:

| Criterion | Points | Question | Activity 2 Scope & Repository Evidence |
|---|---|---|---|
| C1 | 5 | Did you create a GitHub repository for your project? | Public repository [`jdsaire/fullstack_c8_safevault`](https://github.com/jdsaire/fullstack_c8_safevault) extended via Pull Request [#4](https://github.com/jdsaire/fullstack_c8_safevault/pull/4) (`feedc6a`) with `BCrypt.Net-Next` (`4.0.3`) in [`src/SafeVault/SafeVault.csproj`](../../src/SafeVault/SafeVault.csproj) and authentication/RBAC test fixtures in [`Tests/Tests.csproj`](../../Tests/Tests.csproj) (`[M]`). |
| C2 | 5 | Did you use an AI environment to generate secure code for input validation and SQL injection prevention? | Activity 1 input validation and parameterized query defenses ([`src/SafeVault/Services/InputValidator.cs`](../../src/SafeVault/Services/InputValidator.cs), [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs)) are preserved and extended with `ValidateRegistrationInput`, `ValidateLoginInput`, and parameterized `SqliteParameter` bindings across `RegisterUserAsync`, `GetUserAccountByUsernameAsync`, and `UpdateUserRoleAsync` (`[M]`). |
| C3 | 5 | Did you use an AI environment to implement authentication and authorization mechanisms, including role-based access control (RBAC)?? | An AI environment assisted in implementing salted BCrypt password hashing ([`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs)), constant-time login authentication with anti-enumeration ([`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs)), and HMAC-SHA256 session tokens and RBAC route enforcement for `Admin`, `Auditor`, and `User` roles ([`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs), [`src/SafeVault/Program.cs`](../../src/SafeVault/Program.cs)) (`[M]`). |
| C4 | 5 | Did you debug and resolve security vulnerabilities such as SQL injection and XSS? | Activity 2 neutralizes SQL injection payloads on authentication endpoints (`TestLogin_SqlInjectionPayloads_AreNeutralized`, `[M]`) and resolves the signed bitwise XOR modulo bug in client-side token simulation (`6862ffb`). Comprehensive codebase vulnerability debugging and remediation are completed in Activity 3. |
| C5 | 5 | Did you generate and execute tests to verify the application's security? | An AI environment assisted in generating 10 authentication and RBAC unit tests in [`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs), executed alongside the 8 Activity 1 tests in [`Tests/TestInputValidation.cs`](../../Tests/TestInputValidation.cs) via `dotnet test` (`18/18` passed in `4.8264 s`, `0` warnings, `0` errors) (`[M]`). |
| C6 | 5 | Did you include a brief summary of the vulnerabilities identified, the fixes applied, and how the AI environment assisted in the debugging process? | Activity 2 updates [`README.md`](../../README.md) (`e8d4007`) to disclose how an AI environment assisted in implementing password hashing, authentication, RBAC, and the 18-test suite; the complete capstone vulnerability and debugging summary is completed in Activity 3. |

---

## 3. Chronological Evolution & Commit History (PR #4)

Branch `activity-2-auth-rbac` was created from `main` (`e33c374`) and merged via Pull Request [#4](https://github.com/jdsaire/fullstack_c8_safevault/pull/4) (`feedc6a`) across 6 atomic commits:

1. **`43c91e3` — Extend schema and user repository for password hashes and roles (`[M]`)**
   - Updated [`database.sql`](../../database.sql) with `PasswordHash TEXT NOT NULL DEFAULT ''`, `Role TEXT NOT NULL DEFAULT 'User' CHECK (Role IN ('Admin', 'Auditor', 'User'))`, and `CreatedAt`.
   - Extended [`src/SafeVault/Models/UserSubmission.cs`](../../src/SafeVault/Models/UserSubmission.cs) with `RegistrationSubmission`, `LoginRequest`, `RoleAssignmentRequest`, `AuthResult`, `AuthorizationResult`, and `UserRecord` models.
   - Extended [`src/SafeVault/Data/UserRepository.cs`](../../src/SafeVault/Data/UserRepository.cs) with backward-compatible schema migration (`EnsureColumnExists`) and parameterized `RegisterUserAsync`, `GetUserAccountByUsernameAsync`, `UpdateUserRoleAsync`, and `GetAllUsersAsync` methods.
2. **`c3e5a42` — Implement BCrypt password hashing and user authentication service (`[M]`)**
   - Added `BCrypt.Net-Next` (`4.0.3`) to [`src/SafeVault/SafeVault.csproj`](../../src/SafeVault/SafeVault.csproj).
   - Created [`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs) implementing `HashPassword`, `VerifyPassword`, and `InspectHashMetadata` (default work factor `12`, 128-bit salts).
   - Created [`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs) implementing credential validation, `RegisterUserAsync`, and constant-time `AuthenticateAsync` with dummy-hash anti-enumeration.
3. **`0664157` — Implement RBAC authorization service and protected API endpoints (`[M]`)**
   - Created [`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs) implementing `AuthorizeAdminDashboard`, `AuthorizeRoleManagement`, `AuthorizeAuditLogs`, `AuthorizeUserVault`, `AuthorizeByRole`, `IssueSessionToken`, and `ValidateSessionToken` (HMAC-SHA256 with `CryptographicOperations.FixedTimeEquals`).
   - Updated [`src/SafeVault/Program.cs`](../../src/SafeVault/Program.cs) with `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/admin/dashboard`, `POST /api/admin/users/role`, `GET /api/audit/logs`, and `GET /api/vault/profile`.
4. **`4f09713` — Add NUnit security tests for authentication and RBAC enforcement (`[M]`)**
   - Created [`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs) containing 10 NUnit security tests verifying BCrypt salts, login authentication, SQLi resistance on login endpoints, and RBAC route enforcement (`200` / `401` / `403`).
5. **`6862ffb` — Add Cycle 5 authentication and Cycle 6 RBAC multipage workspaces (`[SIM]` Client Fallback)**
   - Created [`cycle5-auth.html`](../../cycle5-auth.html) and [`cycle6-rbac.html`](../../cycle6-rbac.html), and updated [`index.html`](../../index.html), [`cycle1-intake.html`](../../cycle1-intake.html)–[`cycle4-tests.html`](../../cycle4-tests.html), [`webform.html`](../../webform.html), [`css/styles.css`](../../css/styles.css), and [`js/safevault.js`](../../js/safevault.js).
6. **`e8d4007` — Update README documentation for Activity 2 authentication and RBAC**
   - Updated [`README.md`](../../README.md) with Activity 2 architecture, project tree, scope boundaries, and Criterion C3/C5 AI assistance disclosure.

---

## 4. Technical Debugging Deep Dive & Root Cause Analysis (`[M]` vs. `[SIM]`)

### Defect 1: Timing-Based User Enumeration on Non-Existent Login Accounts (`[M]`)
- **Risk**: If `AuthService.AuthenticateAsync` returns immediately when `UserRepository.GetUserAccountByUsernameAsync` returns `null`, an attacker can distinguish valid usernames (~70–120 ms BCrypt verification) from non-existent usernames (< 1 ms database lookup).
- **Resolution**: Precomputed a work-factor-12 dummy BCrypt hash (`DummyHash`) at service initialization in [`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs). When a lookup returns `null`, `PasswordHasher.VerifyPassword(password, DummyHash)` still executes before returning the uniform `401 Unauthorized` failure message (`"Invalid username or password."`), verified by `TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration` (`[M]`).

### Defect 2: Signed Bitwise XOR Modulo in Client-Side Token Simulation ([`js/safevault.js`](../../js/safevault.js) — `[SIM]`)
- **Symptom**: During headless Chrome inspection of [`cycle6-rbac.html`](../../cycle6-rbac.html), the simulated bearer token string in [`js/safevault.js`](../../js/safevault.js) occasionally rendered `undefined` substrings inside the signature segment.
- **Root Cause**: In JavaScript, bitwise XOR (`stateA ^ stateB`) converts 32-bit unsigned integers into signed 32-bit integers. When the sign bit (`0x80000000`) was set, `(stateA ^ stateB) % BCRYPT_ALPHABET.length` evaluated to a negative number, indexing `BCRYPT_ALPHABET[-n] === undefined`.
- **Fix Applied**: Coerced the XOR result to an unsigned 32-bit integer via zero-fill right shift (`>>> 0`) prior to modulo indexing:
  ```javascript
  out += BCRYPT_ALPHABET[((stateA ^ stateB) >>> 0) % BCRYPT_ALPHABET.length];
  ```
  Verified in headless Chrome that simulated tokens rendered valid base64url strings (`[SIM]`).

---

## 5. Security Telemetry & Automated Test Suite Audit (`[M]`)

### Measured NUnit Automated Test Results (`18/18` Passed at Activity 2 Completion — `[M]`)
```text
Test run for Tests/bin/Release/net8.0/Tests.dll (.NETCoreApp,Version=v8.0)
NUnit Adapter 4.5.0.0: Test execution started
Running all tests in Tests/bin/Release/net8.0/Tests.dll
   NUnit3TestExecutor discovered 18 of 18 NUnit test cases using Current Discovery mode, Non-Explicit run
  Passed TestLogin_InvalidPassword_RejectsWithUnauthorized [255 ms]
  Passed TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration [587 ms]
  Passed TestLogin_SqlInjectionPayloads_AreNeutralized [1 s]
  Passed TestLogin_ValidCredentials_AuthenticatesAndIssuesSignedToken [130 ms]
  Passed TestPasswordHashing_GeneratesUniqueSaltsAndVerifiesCorrectly [1 s]
  Passed TestRbac_AdminRole_GrantedAccessToAdminDashboardAndRoleManagement [206 ms]
  Passed TestRbac_AuditorRole_GrantedAuditLogsButDeniedAdminDashboard [135 ms]
  Passed TestRbac_InvalidRoleOrWeakPassword_RejectedDuringRegistration [2 ms]
  Passed TestRbac_StandardUserRole_DeniedAccessToAdminDashboard [129 ms]
  Passed TestRbac_UnauthenticatedOrTamperedToken_DeniedWith401 [129 ms]
  Passed TestForSQLInjection [6 ms]
  Passed TestForXSS [3 ms]
  Passed TestInvalidInput_FailsValidation("","user@test.com","Username is required.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("ab","user@test.com","Username must be between 3 and 50 characters.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("invalid user name with spaces","user@test.com","Username contains invalid characters.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("valid_user","","Email is required.") [< 1 ms]
  Passed TestInvalidInput_FailsValidation("valid_user","not-an-email","Email format is invalid.") [< 1 ms]
  Passed TestValidInput_PassesValidation [< 1 ms]

Test Run Successful.
Total tests: 18
     Passed: 18
     Failed: 0
 Total time: 4.8264 Seconds
```

### Activity 2 Authentication & RBAC Test Coverage Matrix (`[M]` NUnit Execution on Simulated Payloads `[SIM]`)

| NUnit Test Method ([`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs), `[M]`) | Security Scenario / Input (`[SIM]`) | Target Method (`[M]`) | Measured Verdict (`[M]`) |
|---|---|---|---|
| `TestPasswordHashing_GeneratesUniqueSaltsAndVerifiesCorrectly` | Identical plaintext hashed twice; inspected for `$2a$12$` / `$2b$12$` prefix, 60-char length, and distinct 22-char salts | `PasswordHasher.HashPassword` / `InspectHashMetadata` | Unique salts confirmed; `VerifyPassword` returns `true` for match, `false` for mismatch |
| `TestLogin_ValidCredentials_AuthenticatesAndIssuesSignedToken` | Registered `User` authenticates with valid password | `AuthService.AuthenticateAsync` + `AuthorizationService.IssueSessionToken` | `IsAuthenticated = true`, `StatusCode = 200`, valid HMAC-SHA256 token issued |
| `TestLogin_InvalidPassword_RejectsWithUnauthorized` | Registered user submits wrong password (`WrongPass999`) | `AuthService.AuthenticateAsync` | `IsAuthenticated = false`, `StatusCode = 401`, uniform error message |
| `TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration` | Login attempt for unknown username (`ghost_user`) | `AuthService.AuthenticateAsync` | Dummy BCrypt verification runs; returns identical `401` message |
| `TestLogin_SqlInjectionPayloads_AreNeutralized` | Tautology (`admin' OR '1'='1`), comment (`admin'--`), stacked drop (`'; DROP TABLE Users;--`) in login fields | `AuthService.AuthenticateAsync` + `UserRepository.GetUserAccountByUsernameAsync` | All payloads rejected (`401`); `Users` table integrity 100% preserved |
| `TestRbac_AdminRole_GrantedAccessToAdminDashboardAndRoleManagement` | `Admin` bearer token accesses admin dashboard, role management, audit logs, user vault, and promotes a `User` to `Auditor` | `AuthorizationService.AuthorizeAdminDashboard` / `AuthorizeRoleManagement` + `UserRepository.UpdateUserRoleAsync` | `200 OK` on all routes; role updated to `Auditor` |
| `TestRbac_AuditorRole_GrantedAuditLogsButDeniedAdminDashboard` | `Auditor` bearer token probes audit logs, user vault, admin dashboard, and role management | `AuthorizationService.AuthorizeAuditLogs` / `AuthorizeUserVault` / `AuthorizeAdminDashboard` | `200 OK` on audit logs & user vault; `403 Forbidden` on admin dashboard & role management |
| `TestRbac_StandardUserRole_DeniedAccessToAdminDashboard` | `User` bearer token probes admin dashboard, audit logs, and user vault | `AuthorizationService.AuthorizeAdminDashboard` / `AuthorizeAuditLogs` / `AuthorizeUserVault` | `403 Forbidden` on admin dashboard & audit logs; `200 OK` on user vault |
| `TestRbac_UnauthenticatedOrTamperedToken_DeniedWith401` | Empty token, malformed token, and forged payload (`User` swapped to `Admin` in base64url payload) | `AuthorizationService.ValidateSessionToken` / `AuthorizeAdminDashboard` | `401 Unauthorized` on all unauthenticated and tampered tokens |
| `TestRbac_InvalidRoleOrWeakPassword_RejectedDuringRegistration` | Weak password (`short1`) and unsupported role (`SuperRoot`) | `AuthService.RegisterUserAsync` | Registration rejected with `400 Bad Request`; `0` records inserted |

---

## 6. Component Architecture (Activities 1 & 2 Baseline)

```text
fullstack_c8_safevault/
├── .gitignore
├── .nojekyll
├── README.md
├── SafeVault.sln
├── database.sql
├── docs/
│   └── reports/
│       ├── ACTIVITY-1-COMPLETION-REPORT.md
│       ├── ACTIVITY-2-COMPLETION-REPORT.md
│       └── README.md
├── index.html                      # Mission Hub (Activities 1 & 2 overview + 6 cycle cards)
├── cycle1-intake.html              # Cycle 1: Legitimate intake form & live database [SIM]
├── cycle2-sqli.html                # Cycle 2: SQLi attack console & parameter inspector [SIM]
├── cycle3-xss.html                 # Cycle 3: XSS dual-stage sanitization console [SIM]
├── cycle4-tests.html               # Cycle 4: Automated 18-test NUnit suite runner [SIM]
├── cycle5-auth.html                # Cycle 5: Salted BCrypt hash dissector & login simulator [SIM]
├── cycle6-rbac.html                # Cycle 6: RBAC route gate & admin dashboard simulator [SIM]
├── webform.html                    # Standalone intake form page
├── css/
│   └── styles.css                  # Shared WCAG 2.1 AAA dark slate styles + RBAC/hash components
├── js/
│   └── safevault.js                # Shared client-side validation, BCrypt, RBAC & 18-test engine [SIM]
├── src/
│   └── SafeVault/
│       ├── Program.cs              # Minimal API endpoints (/submit, /api/auth/*, /api/admin/*, /api/audit/*, /api/vault/*) [M]
│       ├── SafeVault.csproj        # .NET 8 project with Microsoft.Data.Sqlite & BCrypt.Net-Next 4.0.3
│       ├── Data/
│       │   └── UserRepository.cs   # Parameterized SQLite repository (Create, Register, Lookup, Role Update) [M]
│       ├── Models/
│       │   └── UserSubmission.cs   # DTOs & UserRecord entity [M]
│       └── Services/
│           ├── AuthService.cs          # Registration & constant-time login authentication [M]
│           ├── AuthorizationService.cs # RBAC policy evaluator & HMAC-SHA256 session token service [M]
│           ├── InputValidator.cs       # Regex validation & HTML entity encoding [M]
│           └── PasswordHasher.cs       # BCrypt cost-12 password hashing & salt inspection [M]
└── Tests/
    ├── Tests.csproj
    ├── TestInputValidation.cs      # 8 Activity 1 SQLi, XSS & validation tests [M]
    └── TestAuthAndRbac.cs          # 10 Activity 2 BCrypt, login & RBAC security tests [M]
```

---

## 7. Scope Boundaries: Activity 1, Activity 2, and Activity 3

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                   ACTIVITIES 1 & 2 SCOPE (COMPLETED)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✔ Activity 1: Input Validation, HTML Entity Encoding, Parameterized SQL    │
│  ✔ Activity 2: Salted BCrypt Password Hashing (cost 12, 128-bit salts)      │
│  ✔ Activity 2: Constant-Time Login Authentication & Anti-Enumeration        │
│  ✔ Activity 2: HMAC-SHA256 Session Tokens & RBAC (Admin, Auditor, User)     │
│  ✔ Activities 1 & 2: 18 Automated NUnit Security Tests (100% passing)       │
│  ✔ Activities 1 & 2: 7-Page Interactive Workspace (Cycles 1–6 + Hub)        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼ [ISOLATION BOUNDARY]
┌─────────────────────────────────────────────────────────────────────────────┐
│               ACTIVITY 3 SCOPE (SECURITY DEBUGGING & SUMMARY)               │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Codebase Security Vulnerability Debugging & Remediation Audit (C4)       │
│  • Edge-Case Hardening & Regression Verification Across All Layers (C5)     │
│  • Final Capstone Security Evaluation & AI Disclosure Summary (C6)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Artifact & Verification Audit Ledger

| Artifact Category | Identifier / Target | Location / Hash | Provenance & Status |
|---|---|---|---|
| **Baseline Commit** | Activity 1 Completion Report on `main` | `e33c374` | `[M]` Verified |
| **Pull Request #4** | Activity 2 Auth & RBAC (`activity-2-auth-rbac`) | Merged at `feedc6a` | `[M]` Merged by `jdsaire` |
| **Release Build** | `dotnet build SafeVault.sln -c Release` | `0` warnings, `0` errors | `[M]` Verified |
| **NUnit Test Suite** | `dotnet test SafeVault.sln -c Release` (`Tests/TestInputValidation.cs` + `Tests/TestAuthAndRbac.cs`) | `18` passed, `0` failed (`4.8264 s`) | `[M]` Verified |
| **Interactive Demo** | Static Browser Workspace (`index.html`, `cycle1–6`, `webform.html`) | `https://jdsaire.github.io/fullstack_c8_safevault/` | `[SIM]` Client-side simulation fallback |

---

## 9. Author & AI Assistance Disclosure Attestation

- **Sole Author**: Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`).
- **AI Assistance Summary (Criteria C3 & C5)**: As documented in [`README.md`](../../README.md), an AI environment assisted in implementing salted BCrypt password hashing ([`src/SafeVault/Services/PasswordHasher.cs`](../../src/SafeVault/Services/PasswordHasher.cs)), constant-time authentication with anti-enumeration ([`src/SafeVault/Services/AuthService.cs`](../../src/SafeVault/Services/AuthService.cs)), HMAC-SHA256 bearer token issuance and RBAC route enforcement ([`src/SafeVault/Services/AuthorizationService.cs`](../../src/SafeVault/Services/AuthorizationService.cs)), and the 10 NUnit security tests in [`Tests/TestAuthAndRbac.cs`](../../Tests/TestAuthAndRbac.cs).
- **Build & Test Verification**: All Activity 2 code compiled with `0` warnings and `0` errors under the `.NET 8.0` SDK (`[M]`).
