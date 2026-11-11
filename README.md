# SafeVault

A secure web application designed to manage sensitive user data, cryptographic credentials, and role-based access controls, built as part of the Microsoft Full Stack Developer Specialization (Course 8: *Security and Authentication* Capstone Project).

SafeVault demonstrates defense-in-depth secure coding principles across input validation, parameterized SQL queries (SQLi prevention), HTML entity encoding (XSS mitigation), BCrypt password hashing with unique 128-bit salts, and Role-Based Access Control (RBAC).

**Live Interactive Deployment:** [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/)  
*(Interact with the real-time input validation pipeline, parameterized SQL query inspector, XSS sanitizer, BCrypt password hashing & login verifier, RBAC access matrix simulator, and 18-test NUnit runner directly in your browser).*

---

## Architecture & Security Implementation

### 1. Input Validation and Sanitization (Activity 1)
- **Web Form (`webform.html`, `cycle1-intake.html`)**: Features HTML5 validation constraints (`required`, length boundaries, and regex patterns restricting usernames to safe alphanumeric, underscore, hyphen, and period characters) alongside client-side sanitization routines that strip dangerous script tags and event handlers prior to submission.
- **Validation Service (`src/SafeVault/Services/InputValidator.cs`)**: Server-side defensive boundary enforcing strict structural validation (`IsValidUsername`, `IsValidEmail`, `IsValidPassword`, `IsValidRole`) and HTML entity encoding (`WebUtility.HtmlEncode`) to neutralize stored and reflected XSS payloads.

### 2. Parameterized Database Queries (Activity 1 & Activity 2)
- **Schema (`database.sql`)**: Defines the relational structure for user records (`Users` table with `UserID`, `Username`, `Email`, `PasswordHash`, `Role`, and `CreatedAt`), enforced by a database-level `CHECK (Role IN ('Admin', 'Auditor', 'User'))` constraint.
- **Data Access (`src/SafeVault/Data/UserRepository.cs`)**: All database operations (`CreateUser`, `RegisterUser`, `GetUserByUsername`, `GetUsersByEmail`, `UpdateUserRole`, `GetAllUsers`) utilize parameterized commands (`SqliteParameter`) with SQLite. User-supplied parameters are bound explicitly as literal values (`@Username`, `@Email`, `@PasswordHash`, `@Role`), preventing any interpretation of malicious input as executable SQL logic.

### 3. Cryptographic Authentication & Password Hashing (Activity 2)
- **Password Hasher (`src/SafeVault/Services/PasswordHasher.cs`)**: Uses `BCrypt.Net-Next` (`$2a$` / `$2b$` modular crypt format) with a default cost factor of `12` ($2^{12} = 4,096$ key expansion rounds) and cryptographically random 128-bit salts generated per user registration. Plaintext passwords are never stored or logged.
- **Authentication Service (`src/SafeVault/Services/AuthService.cs`)**: Orchestrates user registration and login verification:
  - Normalizes and validates credentials before hashing or querying.
  - Protects against timing-based account enumeration by verifying against a precomputed dummy BCrypt hash when a requested username does not exist.
  - Returns uniform failure messages (`Invalid username or password.`) for both unknown usernames and mismatched passwords.

### 4. Role-Based Access Control & Session Tokens (Activity 2)
- **Authorization Service (`src/SafeVault/Services/AuthorizationService.cs`)**:
  - **Roles**: `Admin` (full system administration, user management, role assignment, audit logs, and vault access), `Auditor` (read-only compliance audit logs and personal vault profile), and `User` (standard personal vault profile).
  - **Permission Policies**: `AdminDashboard`, `ManageRoles`, `AuditLogs`, and `VaultAccess` evaluated with strict case-sensitive role matching and default-deny behavior for unauthenticated or unrecognized roles.
  - **Signed Session Tokens**: Issues and validates HMAC-SHA256 signed bearer tokens (`base64url(payload).base64url(signature)`) verified via `CryptographicOperations.FixedTimeEquals` to prevent signature forgery or role tampering.
- **Protected API Endpoints (`src/SafeVault/Program.cs`)**:
  - `POST /api/auth/register` & `POST /api/auth/login`: Public credential registration and authentication endpoints.
  - `GET /api/admin/dashboard`: Restricted to `Admin` (`401 Unauthorized` if unauthenticated, `403 Forbidden` for `Auditor` or `User`).
  - `POST /api/admin/users/{username}/role`: Restricted to `Admin` for role promotions/demotions.
  - `GET /api/audit/logs`: Restricted to `Admin` and `Auditor` (`403 Forbidden` for `User`).
  - `GET /api/vault/profile`: Restricted to authenticated users (`Admin`, `Auditor`, `User`).

### 5. Automated Security & Vulnerability Testing (Activity 1 & Activity 2)
- **Activity 1 NUnit Fixture (`Tests/TestInputValidation.cs` — 8 Tests)**:
  - `TestForSQLInjection` (4 tests): Simulates SQL injection attempts (tautologies, stacked `DROP TABLE` queries, inline comments, `UNION SELECT` attacks) against the data access layer.
  - `TestForXSS` (4 tests): Simulates script injection, event handlers, `javascript:` URIs, and legitimate input preservation.
- **Activity 2 NUnit Fixture (`Tests/TestAuthAndRbac.cs` — 10 Tests)**:
  - `TestPasswordHasher_ProducesSaltedBcryptHash_AndVerifiesCorrectly`: Confirms `$2a$`/`$2b$` format, non-plaintext storage, and unique per-invocation salts.
  - `TestPasswordHasher_RejectsWrongPassword_AndInvalidWorkFactor`: Confirms wrong password rejection and work factor range enforcement (`4–31`).
  - `TestRegisterAndLogin_ValidCredentials_ReturnsAuthenticatedSession`: Confirms end-to-end registration, BCrypt hash persistence, and login token issuance.
  - `TestLogin_InvalidPasswordAndUnknownUser_ReturnsUniformFailure`: Confirms uniform rejection for wrong passwords and unknown accounts.
  - `TestLogin_SqlInjectionInUsernameAndPassword_IsBlockedAndParameterized`: Confirms SQLi tautologies in login fields cannot bypass authentication or corrupt the `Users` table.
  - `TestRbac_AdminRole_GrantedAccessToAdminAuditAndVaultEndpoints`: Confirms `Admin` access across all policy gates (`200 OK`).
  - `TestRbac_AuditorRole_GrantedAuditAndVault_DeniedAdminDashboard`: Confirms `Auditor` receives `200 OK` on `/api/audit/logs` and `403 Forbidden` on `/api/admin/dashboard`.
  - `TestRbac_StandardUserRole_GrantedVault_DeniedAdminAndAuditEndpoints`: Confirms `User` receives `200 OK` on `/api/vault/profile` and `403 Forbidden` on admin and audit routes.
  - `TestRbac_UnauthenticatedAndTamperedToken_Returns401Unauthorized`: Confirms missing or payload-tampered bearer tokens return `401 Unauthorized`.
  - `TestRbac_RolePromotion_OnlyAdminCanPromoteUserRole`: Confirms only `Admin` can promote a `User` to `Auditor` or `Admin`.

### 6. Multipage Architecture & Quarantined Telemetry Inspector
- **Multipage Navigation**: Modularized into 7 dedicated verification environments:
  - **Hub (`index.html`)**: Executive mission overview, security boundary disclosure, and navigation links across all 6 cycles.
  - **Cycle 1 (`cycle1-intake.html`)**: Valid user registration, regex validation badges, and live relational store view.
  - **Cycle 2 (`cycle2-sqli.html`)**: SQL injection attack simulation (tautologies, stacked drops, comments) and parameter inspection.
  - **Cycle 3 (`cycle3-xss.html`)**: Cross-Site Scripting defense with dual-stage sanitization (tag stripping and entity encoding).
  - **Cycle 4 (`cycle4-tests.html`)**: Automated NUnit test suite runner executing all 18 security assertions live in-browser.
  - **Cycle 5 (`cycle5-auth.html`)**: BCrypt password hashing laboratory (`$2a$12$...` structure dissector) and live authentication verifier (valid login, wrong password, unknown user, SQLi login bypass attempt).
  - **Cycle 6 (`cycle6-rbac.html`)**: Role-Based Access Control policy simulator (`Anonymous`, `User`, `Auditor`, `Admin`, `Tampered Token`) against protected API endpoints with live `200 OK` / `401 Unauthorized` / `403 Forbidden` enforcement.
  - **Standalone Form (`webform.html`)**: Direct access to the hardened intake form.
- **Quarantined Telemetry Panels**: Each cycle incorporates a collapsible, accessible telemetry inspector (with Show/Hide, Copy Code, and Reset controls) to inspect generated parameterized SQL, entity transforms, BCrypt hash structures, RBAC authorization traces, or test execution logs.
- **WCAG 2.1 AAA Accessibility**: 16px base font, 18px card headers, 14.5px code, high contrast ratios (>= 12:1), and 44px+ touch targets.

---

## Scope Boundaries Across Capstone Activities

SafeVault is developed iteratively across the Course 8 capstone activities:
- **Activity 1 Scope (Complete)**: Defensive Input Validation, Sanitization, Parameterized SQLite Queries (SQLi prevention), and Automated NUnit Vulnerability Tests (8 tests).
- **Activity 2 Scope (Complete)**: User Authentication, BCrypt Password Hashing with 128-bit Salts, HMAC-SHA256 Signed Session Tokens, Role-Based Access Control (`Admin`, `Auditor`, `User`), and Automated Auth/RBAC NUnit Security Tests (10 additional tests, 18 total).
- **Activity 3 Scope (Subsequent)**: Security Debugging, Vulnerability Remediation Audit, and Final Capstone Summary Report (Criteria C4 & C6).

---

## Project Structure

```
├── .gitignore
├── .nojekyll
├── README.md
├── SafeVault.sln
├── database.sql
├── index.html
├── cycle1-intake.html
├── cycle2-sqli.html
├── cycle3-xss.html
├── cycle4-tests.html
├── cycle5-auth.html
├── cycle6-rbac.html
├── webform.html
├── css/
│   └── styles.css
├── js/
│   └── safevault.js
├── docs/
│   └── reports/
│       ├── ACTIVITY-1-COMPLETION-REPORT.md
│       ├── ACTIVITY-2-COMPLETION-REPORT.md
│       └── README.md
├── src/
│   └── SafeVault/
│       ├── Data/
│       │   └── UserRepository.cs
│       ├── Models/
│       │   └── UserSubmission.cs
│       ├── Services/
│       │   ├── AuthService.cs
│       │   ├── AuthorizationService.cs
│       │   ├── InputValidator.cs
│       │   └── PasswordHasher.cs
│       ├── Program.cs
│       └── SafeVault.csproj
└── Tests/
    ├── TestAuthAndRbac.cs
    ├── TestInputValidation.cs
    └── Tests.csproj
```

---

## Build and Test Execution

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build Solution
```bash
dotnet build SafeVault.sln -c Release
```

### Run Security & Vulnerability Tests
```bash
dotnet test SafeVault.sln --logger "console;verbosity=detailed"
```

All 18 unit tests execute against an isolated in-memory SQLite database to verify input validation, SQLi prevention, XSS encoding, BCrypt password hashing, login authentication, and RBAC route enforcement.

---

## AI Assistance Disclosure

*This section provides transparent disclosure of tool usage in accordance with the capstone evaluation criteria (Criteria C2, C3, C5, and C6).*

During the development of SafeVault Activities 1 and 2, an AI environment was utilized to support secure design, authentication implementation, and security testing:
1. **Input Validation and Sanitization (Criterion C2)**: An AI environment assisted in refining regular expression patterns and structuring the dual-stage sanitization pipeline to neutralize Cross-Site Scripting (XSS) vectors across form fields.
2. **SQL Injection Prevention (Criterion C2)**: An AI environment assisted in designing parameterized query structures, verifying placeholder bindings (`SqliteParameter`), and ensuring that user inputs are never concatenated directly into SQL command strings.
3. **Authentication and Role-Based Access Control (Criterion C3)**: An AI environment assisted in structuring the BCrypt password hashing service (`PasswordHasher.cs`) with per-user cryptographic salts and work factor configuration, designing constant-time credential verification with anti-enumeration protections (`AuthService.cs`), and implementing Role-Based Access Control policies and signed session token verification (`AuthorizationService.cs`) to restrict administrative and audit routes (`401 Unauthorized` / `403 Forbidden`).
4. **Security Test Formulation (Criterion C5)**: An AI environment assisted in compiling realistic attack payloads and access-control test scenarios across `Tests/TestInputValidation.cs` and `Tests/TestAuthAndRbac.cs`, verifying that SQL injection, XSS, invalid credentials, tampered session tokens, and unauthorized privilege escalation attempts are reliably blocked.
