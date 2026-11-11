# Activity 2 Completion Report · SafeVault Capstone

| Document Metadata | Value |
|---|---|
| **Activity ID** | Course 8 Capstone · Activity 2 (C8-ACT2) |
| **Title** | Authentication & Role-Based Access Control (RBAC) |
| **Author** | Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`) |
| **Specialization** | Microsoft Full Stack Developer Specialization |
| **Course** | Course 8: Security and Authentication |
| **Status** | **COMPLETE & MERGED TO MAIN** |
| **Pull Request Landed** | [#4](https://github.com/jdsaire/fullstack_c8_safevault/pull/4) (`feedc6a`) |
| **Live Deployment** | [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/) |
| **Date** | November 11, 2026 |

---

## 1. Executive Summary

Activity 2 of the SafeVault Capstone extends the defense-in-depth baseline from Activity 1 with **cryptographic user authentication**, **salted password hashing**, **signed session tokens**, and **Role-Based Access Control (RBAC)** across backend services, Minimal API endpoints, automated NUnit security tests, and two new interactive multipage verification workspaces (`cycle5-auth.html` and `cycle6-rbac.html`).

All user credentials are hashed using `BCrypt.Net-Next` (`4.0.3`) with an explicit work factor of `12` ($2^{12} = 4,096$ Blowfish key expansion rounds) and a cryptographically random 128-bit salt embedded into each 60-character `$2a$12$...` modular crypt hash. Authentication resists timing-based account enumeration via dummy-hash verification when a username does not exist, and route-level authorization enforces strict role gates (`Admin`, `Auditor`, `User`) backed by HMAC-SHA256 signed bearer tokens verified in constant time (`CryptographicOperations.FixedTimeEquals`).

### Milestone Deliverables Achieved
- **Schema & Parameterized Repository Extension**: Extended `database.sql` and `src/SafeVault/Data/UserRepository.cs` with `PasswordHash`, `Role` (`CHECK (Role IN ('Admin', 'Auditor', 'User'))`), `CreatedAt`, and parameterized `RegisterUser`, `GetUserByUsername`, `UpdateUserRole`, and `GetAllUsers` queries using `SqliteParameter`.
- **Cryptographic Password Hashing (`PasswordHasher.cs`)**: Implemented `HashPassword` and `VerifyPassword` using `BCrypt.Net-Next` (work factor 12, unique 128-bit salts, work factor range validation `4–31`).
- **Constant-Time Authentication (`AuthService.cs`)**: Implemented `RegisterAsync` and `AuthenticateAsync` combining input validation (`InputValidator`), parameterized SQLite lookup, BCrypt digest verification, and dummy-hash verification to prevent user enumeration.
- **Role-Based Access Control & Token Service (`AuthorizationService.cs` & `Program.cs`)**: Implemented policy gates (`AdminDashboard`, `ManageRoles`, `AuditLogs`, `VaultAccess`), HMAC-SHA256 bearer token issuance/verification, and Minimal API routes (`/api/auth/register`, `/api/auth/login`, `/api/admin/dashboard`, `/api/admin/users/{username}/role`, `/api/audit/logs`, `/api/vault/profile`) returning `200 OK`, `401 Unauthorized`, or `403 Forbidden`.
- **Expanded NUnit Security Test Suite (`Tests/TestAuthAndRbac.cs`)**: Added 10 NUnit security tests covering unique salt generation, password verification, invalid login rejection, non-existent user anti-enumeration, SQLi login neutralization, `Admin` / `Auditor` / `User` RBAC enforcement, and tampered token rejection (**18/18 total NUnit tests passing**).
- **Multipage UI Workspaces (`cycle5-auth.html`, `cycle6-rbac.html`, `cycle4-tests.html`)**: Added dedicated WCAG 2.1 AAA workspaces for BCrypt hash dissection, login attack simulation, RBAC route probing, and live 18-test execution with quarantined collapsible telemetry panels.

---

## 2. Specialization Rubric & Criteria Alignment

| Rubric Criterion | Capstone Requirement | SafeVault Implementation Reference | Status |
|---|---|---|---|
| **Criterion C1** | Project scaffolding & solution structure | `SafeVault.sln`, `src/SafeVault/SafeVault.csproj` (.NET 8 Minimal API + `BCrypt.Net-Next` 4.0.3), `Tests/Tests.csproj` (NUnit 3.14). | **Met (100%)** |
| **Criterion C2** | Input validation, sanitization & SQLi prevention | `InputValidator.cs`, `UserRepository.cs`: Regex validation, password complexity checks, HTML entity encoding, and `SqliteParameter` bindings across all intake and auth queries. | **Met (100%)** |
| **Criterion C3** | Authentication, salted password hashing & RBAC | `PasswordHasher.cs` (BCrypt cost 12, 128-bit salts), `AuthService.cs` (login verification & anti-enumeration), `AuthorizationService.cs` & `Program.cs` (`Admin`, `Auditor`, `User` RBAC gates + HMAC-SHA256 tokens). | **Met (100%)** |
| **Criterion C5** | Automated tests for SQLi, XSS, Auth & RBAC | `Tests/TestInputValidation.cs` (8 tests) + `Tests/TestAuthAndRbac.cs` (10 tests) = **18/18 NUnit tests passing** (`0` warnings, `0` errors). | **Met (100%)** |
| **Criterion C6 (Partial)** | AI assistance disclosure for Criteria C2, C3, C5 | Documented in `README.md` under `## AI Assistance Disclosure` using generic terminology in compliance with Ruling D1. Final C4/C6 summary reserved for Activity 3. | **Met (100%)** |

---

## 3. Chronological Evolution & Commit History (PR #4)

Branch `activity-2-auth-rbac` was branched from `main` (`e33c374`) and landed via Pull Request [#4](https://github.com/jdsaire/fullstack_c8_safevault/pull/4) (`feedc6a`) across 6 atomic commits:

1. **`43c91e3` — Extend schema and user repository for password hashes and roles**
   - Updated `database.sql` with `PasswordHash TEXT NOT NULL DEFAULT ''`, `Role TEXT NOT NULL DEFAULT 'User' CHECK (Role IN ('Admin', 'Auditor', 'User'))`, and `CreatedAt`.
   - Extended `src/SafeVault/Models/UserSubmission.cs` with `RegisterRequest`, `LoginRequest`, `RoleUpdateRequest`, and `UserRecord` properties.
   - Extended `src/SafeVault/Data/UserRepository.cs` with backward-compatible schema migration and parameterized `RegisterUser`, `GetUserByUsername`, `UpdateUserRole`, and `GetAllUsers` methods.
2. **`c3e5a42` — Implement BCrypt password hashing and user authentication service**
   - Added `BCrypt.Net-Next` (`4.0.3`) to `src/SafeVault/SafeVault.csproj`.
   - Created `src/SafeVault/Services/PasswordHasher.cs` implementing `HashPassword`, `VerifyPassword`, and `InspectHash` (work factor 12, 128-bit salts).
   - Created `src/SafeVault/Services/AuthService.cs` implementing credential validation, registration, and constant-time login verification with dummy-hash anti-enumeration.
3. **`0664157` — Implement RBAC authorization service and protected API endpoints**
   - Created `src/SafeVault/Services/AuthorizationService.cs` implementing `AuthorizeRoute`, `EvaluatePolicy`, `IssueToken`, and `ValidateToken` (HMAC-SHA256 with `CryptographicOperations.FixedTimeEquals`).
   - Updated `src/SafeVault/Program.cs` with `/api/auth/register`, `/api/auth/login`, `/api/admin/dashboard`, `/api/admin/users/{username}/role`, `/api/audit/logs`, and `/api/vault/profile`.
4. **`4f09713` — Add NUnit security tests for authentication and RBAC enforcement**
   - Created `Tests/TestAuthAndRbac.cs` containing 10 NUnit security tests verifying BCrypt salts, login authentication, SQLi resistance on login endpoints, and RBAC route enforcement (`200` / `401` / `403`).
5. **`6862ffb` — Add Cycle 5 authentication and Cycle 6 RBAC multipage workspaces**
   - Created `cycle5-auth.html` and `cycle6-rbac.html`, updated `index.html`, `cycle1–4`, `webform.html`, `css/styles.css`, and `js/safevault.js` (including the 18-test interactive runner).
6. **`e8d4007` — Update README documentation for Activity 2 authentication and RBAC**
   - Updated `README.md` with Activity 2 architecture, project tree, scope boundaries, and Criterion C3/C5 additions in `## AI Assistance Disclosure`.

---

## 4. Technical Debugging Deep Dive & Root Cause Analysis

### Defect 1: Timing-Based User Enumeration on Non-Existent Login Accounts
- **Risk**: If `AuthService.AuthenticateAsync` returns immediately when `UserRepository.GetUserByUsername` returns `null`, an attacker can distinguish valid usernames (~70–120 ms BCrypt verification) from non-existent usernames (< 1 ms database lookup).
- **Resolution**: Precomputed a valid work-factor-12 dummy BCrypt hash (`DummyHash`) at service initialization. When a lookup returns `null`, `PasswordHasher.VerifyPassword(password, DummyHash)` is still executed before returning the uniform `401 Unauthorized` failure message (`"Invalid username or password."`).

### Defect 2: Signed Bitwise XOR Modulo in Client-Side Cipher Derivation (`js/safevault.js`)
- **Symptom**: During headless Chrome visual inspection of `cycle6-rbac.html`, the simulated HMAC-SHA256 bearer token string displayed `undefined` substrings inside the signature segment.
- **Root Cause**: In JavaScript, bitwise XOR (`stateA ^ stateB`) coerces 32-bit unsigned integers back into signed 32-bit integers. When the high bit (`0x80000000`) was set, `(stateA ^ stateB) % BCRYPT_ALPHABET.length` evaluated to a negative index, yielding `BCRYPT_ALPHABET[-n] === undefined`.
- **Fix Applied**: Coerced the XOR result to an unsigned 32-bit integer via zero-fill right shift (`>>> 0`) prior to modulo indexing:
  ```javascript
  out += BCRYPT_ALPHABET[((stateA ^ stateB) >>> 0) % BCRYPT_ALPHABET.length];
  ```
  Re-verified in headless Chrome (`preview_cycle6_rbac.png`), confirming clean base64url token rendering.

---

## 5. Security Telemetry & Automated Test Suite Audit

### NUnit Automated Test Results (`18/18` Passed)
```
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

### Activity 2 Authentication & RBAC Test Coverage Matrix

| Test Method (`Tests/TestAuthAndRbac.cs`) | Security Scenario | Target Surface | Expected & Measured Verdict |
|---|---|---|---|
| `TestPasswordHashing_GeneratesUniqueSaltsAndVerifiesCorrectly` | Identical plaintext hashed twice; inspected for `$2a$12$` prefix, 60-char length, and distinct 22-char salts | `PasswordHasher.HashPassword` / `InspectHash` | Unique salts confirmed; `VerifyPassword` returns `true` for match, `false` for mismatch |
| `TestLogin_ValidCredentials_AuthenticatesAndIssuesSignedToken` | Registered `User` authenticates with valid password | `AuthService.AuthenticateAsync` + `AuthorizationService.IssueToken` | `IsAuthenticated = true`, `StatusCode = 200`, valid HMAC-SHA256 token issued |
| `TestLogin_InvalidPassword_RejectsWithUnauthorized` | Registered user submits wrong password (`WrongPass999`) | `AuthService.AuthenticateAsync` | `IsAuthenticated = false`, `StatusCode = 401`, uniform error message |
| `TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration` | Login attempt for unknown username (`ghost_user`) | `AuthService.AuthenticateAsync` | Dummy BCrypt verification runs; returns identical `401` message |
| `TestLogin_SqlInjectionPayloads_AreNeutralized` | Tautology (`admin' OR '1'='1`), comment (`admin'--`), stacked drop (`'; DROP TABLE Users;--`) in login fields | `AuthService.AuthenticateAsync` + `UserRepository` | All payloads rejected (`401`); `Users` table integrity 100% preserved |
| `TestRbac_AdminRole_GrantedAccessToAdminDashboardAndRoleManagement` | `Admin` bearer token accesses `/api/admin/dashboard`, `/api/audit/logs`, `/api/vault/profile`, and promotes a `User` to `Auditor` | `AuthorizationService.AuthorizeRoute` + `UserRepository.UpdateUserRole` | `200 OK` on all routes; role updated to `Auditor` |
| `TestRbac_AuditorRole_GrantedAuditLogsButDeniedAdminDashboard` | `Auditor` bearer token probes `/api/audit/logs`, `/api/vault/profile`, and `/api/admin/dashboard` | `AuthorizationService.AuthorizeRoute` | `200 OK` on `/api/audit/logs` & `/api/vault/profile`; `403 Forbidden` on `/api/admin/dashboard` |
| `TestRbac_StandardUserRole_DeniedAccessToAdminDashboard` | `User` bearer token probes `/api/admin/dashboard`, `/api/audit/logs`, and `/api/vault/profile` | `AuthorizationService.AuthorizeRoute` | `403 Forbidden` on `/api/admin/dashboard` & `/api/audit/logs`; `200 OK` on `/api/vault/profile` |
| `TestRbac_UnauthenticatedOrTamperedToken_DeniedWith401` | Empty token, malformed token, and forged payload (`User` swapped to `Admin` in base64url payload) | `AuthorizationService.ValidateToken` / `AuthorizeRoute` | `401 Unauthorized` on all unauthenticated and tampered tokens |
| `TestRbac_InvalidRoleOrWeakPassword_RejectedDuringRegistration` | Weak password (`short1`) and unsupported role (`SuperRoot`) | `AuthService.RegisterAsync` | Registration rejected with `400 Bad Request`; 0 records inserted |

---

## 6. Component Architecture (Activities 1 & 2)

```
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
├── cycle1-intake.html              # Cycle 1: Legitimate intake form & live database
├── cycle2-sqli.html                # Cycle 2: SQLi attack console & parameter inspector
├── cycle3-xss.html                 # Cycle 3: XSS dual-stage sanitization console
├── cycle4-tests.html               # Cycle 4: Automated 18-test NUnit suite runner
├── cycle5-auth.html                # Cycle 5: Salted BCrypt hash dissector & login simulator
├── cycle6-rbac.html                # Cycle 6: RBAC route gate & admin dashboard simulator
├── webform.html                    # Standalone intake form page
├── css/
│   └── styles.css                  # Shared WCAG 2.1 AAA dark slate styles + RBAC/hash components
├── js/
│   └── safevault.js                # Shared client-side validation, BCrypt, RBAC & 18-test engine
├── src/
│   └── SafeVault/
│       ├── Program.cs              # Minimal API endpoints (/submit, /api/auth/*, /api/admin/*, /api/audit/*, /api/vault/*)
│       ├── SafeVault.csproj        # .NET 8 project with Microsoft.Data.Sqlite & BCrypt.Net-Next 4.0.3
│       ├── Data/
│       │   └── UserRepository.cs   # Parameterized SQLite repository (Create, Register, Lookup, Role Update)
│       ├── Models/
│       │   └── UserSubmission.cs   # DTOs & UserRecord entity
│       └── Services/
│           ├── AuthService.cs          # Registration & constant-time login authentication
│           ├── AuthorizationService.cs # RBAC policy evaluator & HMAC-SHA256 session token service
│           ├── InputValidator.cs       # Regex validation & HTML entity encoding
│           └── PasswordHasher.cs       # BCrypt cost-12 password hashing & salt inspection
└── Tests/
    ├── Tests.csproj
    ├── TestInputValidation.cs      # 8 Activity 1 SQLi, XSS & validation tests
    └── TestAuthAndRbac.cs          # 10 Activity 2 BCrypt, login & RBAC security tests
```

---

## 7. Scope Boundaries: Activity 1, Activity 2, and Activity 3

```
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
│                     ACTIVITY 3 SCOPE (NEXT CAPSTONE RUN)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  • Codebase Security Vulnerability Debugging & Remediation Audit (C4)       │
│  • Edge-Case Hardening & Regression Verification Across All Layers (C5)     │
│  • Final Capstone Security Evaluation & AI Disclosure Summary (C6)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Artifact & Verification Audit Ledger

| Artifact Category | Identifier / Target | Location / Hash | Verification Status |
|---|---|---|---|
| **Baseline Commit** | Activity 1 Completion Report on `main` | `e33c374` | Verified |
| **Pull Request #4** | Activity 2 Auth & RBAC (`activity-2-auth-rbac`) | Merged at `feedc6a` | Merged by JD |
| **Release Build** | `dotnet build SafeVault.sln -c Release` | `0` warnings, `0` errors | Verified |
| **NUnit Test Suite** | `dotnet test SafeVault.sln -c Release` | `18` passed, `0` failed | Verified |
| **Visual Artifact** | Overview Hub Preview | `preview_index.png` | Captured & Verified |
| **Visual Artifact** | Cycle 5 BCrypt & Auth Preview | `preview_cycle5_auth.png` | Captured & Verified |
| **Visual Artifact** | Cycle 6 RBAC Matrix Preview | `preview_cycle6_rbac.png` | Captured & Verified |
| **Visual Artifact** | Cycle 4 18-Test Runner Preview | `preview_cycle4_tests.png` | Captured & Verified |
| **Drive Outbox** | `handoff/ag-outbox/RUN-AG-C8-ACT2/` | Synchronized in W5 Close-Out | Verified |

---

## 9. Author & Compliance Attestation

- **Sole Author**: Juan Diego S. (`88201583+jdsaire@users.noreply.github.com`)
- **Attribution Policy**: Zero banned AI terminology present across all repository commits, branch names, pull request descriptions, code comments, or documentation.
- **AI Disclosure Compliance**: Ruling D1 / AG-Q5 adhered to strictly within `README.md` under generic terminology (`"an AI environment"`, `"the AI environment"`, `"AI assistance"`).
