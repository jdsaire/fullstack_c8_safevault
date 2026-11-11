# SafeVault

A secure web application designed to manage sensitive user data, cryptographic credentials, role-based access controls, and defense-in-depth vulnerability remediation, built as part of the Microsoft Full Stack Developer Specialization (Course 8: *Security and Authentication* Capstone Project).

SafeVault demonstrates end-to-end secure coding principles across strict input validation, parameterized SQL queries and wildcard-safe directory search (SQLi prevention), multi-layer XSS sanitization and HTML entity encoding, BCrypt password hashing with unique 128-bit salts, HMAC-SHA256 session token integrity, Role-Based Access Control (RBAC), defensive HTTP security headers, and a 28-test NUnit verification suite.

**Live Interactive Deployment:** [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/)  
*(Interact with the real-time input validation pipeline, parameterized SQL query inspector, XSS sanitizer, BCrypt password hashing & login verifier, RBAC access matrix simulator, Activity 3 vulnerability debugging & parameterized search workspace, and 28-test NUnit runner directly in your browser).*

---

## Architecture & Security Implementation

### 1. Input Validation and Sanitization (Activity 1 & Activity 3 Hardening)
- **Web Form (`webform.html`, `cycle1-intake.html`)**: Enforces HTML5 validation constraints (`required`, length boundaries, and regex patterns restricting usernames to safe alphanumeric, underscore, hyphen, and period characters) alongside client-side sanitization routines that strip ASCII control characters, dangerous script tags, obfuscated event handlers, and executable URI protocols prior to submission.
- **Validation Service (`src/SafeVault/Services/InputValidator.cs`)**: Server-side defensive boundary enforcing:
  - Explicit `250ms` `RegexTimeout` across all compiled regular expressions to prevent catastrophic backtracking (ReDoS).
  - Strict username validation (`^[a-zA-Z0-9_\-\.]{3,50}$`) and hardened RFC email validation (`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`) with an explicit character blocklist (`<`, `>`, `"`, `'`, `;`, `(`, `)`, `|`, `\`, `` ` ``) and ASCII control-character rejection (`ContainsControlCharacters`).
  - Multi-stage `Sanitize()` pipeline that strips non-printable control characters, removes HTML tags, strips all `\bon[a-z0-9_]+\s*=` inline event attributes and whitespace-obfuscated `javascript:`, `vbscript:`, and `data:text/html` URI schemes, and applies `WebUtility.HtmlEncode`.

### 2. Parameterized Database Queries & Wildcard-Safe Search (Activities 1–3)
- **Schema (`database.sql`, `UserRepository.InitializeSchema()`)**: Defines the relational structure for user records (`Users` table with `UserID`, `Username UNIQUE`, `Email`, `PasswordHash`, `Role`, and `CreatedAt`), enforced by a `UNIQUE` index on `Username` (`idx_users_username`) and a database-level `CHECK (Role IN ('Admin', 'Auditor', 'User'))` constraint.
- **Data Access (`src/SafeVault/Data/UserRepository.cs`)**:
  - All database operations (`CreateUserAsync`, `RegisterUserAsync`, `GetUserByUsernameAsync`, `GetUserAccountByUsernameAsync`, `GetUsersByEmailAsync`, `SearchUsersAsync`, `UpdateUserRoleAsync`, `GetAllUsersAsync`) execute via parameterized `SqliteCommand` instances (`SqliteParameter`).
  - **Parameterized Search (`SearchUsersAsync`)**: Escapes literal SQLite wildcard characters (`\`, `%`, `_`) via `InputValidator.EscapeSqlLikeWildcards()` before binding `@SearchPattern` in `WHERE Username LIKE @SearchPattern ESCAPE '\' OR Email LIKE @SearchPattern ESCAPE '\'`, preventing both SQL injection tautologies and unescaped `%` wildcard directory dumps.
  - **DDL Identifier Allowlist (`EnsureColumnExists`)**: Validates schema migration column names and SQL types against a static `AllowedSchemaColumns` dictionary (`InvalidOperationException` on unwhitelisted identifiers).

### 3. Cryptographic Authentication & Password Hashing (Activities 2 & 3)
- **Password Hasher (`src/SafeVault/Services/PasswordHasher.cs`)**: Uses `BCrypt.Net-Next` (`$2a$` / `$2b$` modular crypt format) with a default cost factor of `12` ($2^{12} = 4,096$ key expansion rounds), enforced standard BCrypt work factor bounds (`MinWorkFactor = 4`, `MaxWorkFactor = 31`), and cryptographically random 128-bit salts generated per user registration. Plaintext passwords are never stored or logged.
- **Authentication Service (`src/SafeVault/Services/AuthService.cs`)**:
  - Normalizes and validates credentials before hashing or querying (`409 Conflict` on duplicate usernames).
  - Protects against timing-based account enumeration by verifying against a precomputed dummy BCrypt hash when a requested username does not exist.
  - Returns uniform failure messages (`Invalid username or password.`) for both unknown usernames and mismatched passwords.

### 4. Role-Based Access Control, Session Token Integrity & Security Headers (Activities 2 & 3)
- **Authorization Service (`src/SafeVault/Services/AuthorizationService.cs`)**:
  - **Roles**: `Admin` (full system administration, user management, role assignment, audit logs, and vault access), `Auditor` (read-only compliance audit logs and personal vault profile), and `User` (standard personal vault profile).
  - **Signed Session Tokens**: Issues and validates HMAC-SHA256 signed bearer tokens (`base64url(payload).base64url(signature)`) verified via `CryptographicOperations.FixedTimeEquals`. Explicitly rejects pipe (`|`) delimiter characters, ASCII control characters, and non-positive user IDs during both token issuance and claim parsing to prevent claim-delimiter privilege escalation.
- **Defensive HTTP Security Headers & API Endpoints (`src/SafeVault/Program.cs`)**:
  - Emits `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-XSS-Protection: 0`, and `Content-Security-Policy` across all HTTP responses.
  - `POST /submit` & `GET /api/users/{username}`: Validated intake (`409 Conflict` on duplicate username) and input-validated user lookup.
  - `GET /api/users/search?q={term}`: Parameterized, wildcard-escaped user directory search endpoint.
  - `GET /api/security/audit` & `POST /api/security/probe`: Activity 3 vulnerability ledger (`[M]` vs `[SIM]`) and live remediation verification endpoints (`SecurityAuditService.cs`).
  - `POST /api/auth/register` & `POST /api/auth/login`: Public credential registration and authentication endpoints.
  - `GET /api/admin/dashboard` & `POST /api/admin/users/role`: Restricted to `Admin` (`401 Unauthorized` / `403 Forbidden`).
  - `GET /api/audit/logs`: Restricted to `Admin` and `Auditor`.
  - `GET /api/vault/profile`: Restricted to authenticated users (`Admin`, `Auditor`, `User`).

### 5. Automated Security, RBAC & Vulnerability Remediation Testing (28 NUnit Tests)
- **Activity 1 NUnit Fixture (`Tests/TestInputValidation.cs` — 8 Tests)**:
  - `TestForSQLInjection`: Verifies tautologies, stacked `DROP TABLE` queries, inline comments, and `UNION SELECT` payloads are bound as inert literals.
  - `TestForXSS`: Verifies `<script>`, `<img onerror>`, `<svg onload>`, `<iframe src="javascript:...">`, and event handlers are stripped and HTML-encoded.
  - `TestValidInput_PassesValidation` & `TestInvalidInput_FailsValidation` (5 `[TestCase]` cases): Verifies empty, short, malformed, and valid username/email inputs.
- **Activity 2 NUnit Fixture (`Tests/TestAuthAndRbac.cs` — 10 Tests)**:
  - `TestPasswordHashing_GeneratesUniqueSaltsAndVerifiesCorrectly`
  - `TestLogin_ValidCredentials_AuthenticatesAndIssuesSignedToken`
  - `TestLogin_InvalidPassword_RejectsWithUnauthorized`
  - `TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration`
  - `TestLogin_SqlInjectionPayloads_AreNeutralized`
  - `TestRbac_AdminRole_GrantedAccessToAdminDashboardAndRoleManagement`
  - `TestRbac_StandardUserRole_DeniedAccessToAdminDashboard`
  - `TestRbac_AuditorRole_GrantedAuditLogsButDeniedAdminDashboard`
  - `TestRbac_UnauthenticatedOrTamperedToken_DeniedWith401`
  - `TestRbac_InvalidRoleOrWeakPassword_RejectedDuringRegistration`
- **Activity 3 NUnit Fixture (`Tests/TestVulnerabilityRemediation.cs` — 10 Tests)**:
  - `TestEmailValidation_RejectsEmbeddedXssAndSqlPayloads`
  - `TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols`
  - `TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards`
  - `TestUniqueUsernameConstraint_PreventsDuplicateIntakeAndRegistration`
  - `TestSchemaMigration_RejectsUnwhitelistedColumnIdentifier`
  - `TestSessionToken_RejectsPipeDelimiterInjectionInUsername`
  - `TestPasswordHasher_EnforcesStandardWorkFactorBounds`
  - `TestAuthAndLookup_RejectsNullBytesAndOversizedPayloads`
  - `TestSecurityAuditService_DistinguishesMeasuredAndSimulatedFindings`
  - `TestEndToEndRegression_AllSecurityLayersRemainIntact`

### 6. Multipage Architecture & Quarantined Telemetry Inspector
- **Multipage Navigation**: Modularized into 8 dedicated verification environments:
  - **Hub (`index.html`)**: Executive mission overview, cumulative architecture summary, and navigation across all 7 cycles.
  - **Cycle 1 (`cycle1-intake.html`)**: Valid user registration, regex validation badges, and live relational store view.
  - **Cycle 2 (`cycle2-sqli.html`)**: SQL injection attack simulation and `SqliteParameter` inspection.
  - **Cycle 3 (`cycle3-xss.html`)**: Cross-Site Scripting defense with dual-stage sanitization and entity encoding.
  - **Cycle 4 (`cycle4-tests.html`)**: Automated NUnit test suite runner executing all 28 security assertions live in-browser.
  - **Cycle 5 (`cycle5-auth.html`)**: BCrypt password hashing laboratory (`$2a$12$...` structure dissector) and live authentication verifier.
  - **Cycle 6 (`cycle6-rbac.html`)**: Role-Based Access Control policy simulator across `Admin`, `Auditor`, `User`, `Guest`, and tampered tokens.
  - **Cycle 7 (`cycle7-debug.html`)**: Activity 3 vulnerability debugging & remediation audit workspace featuring side-by-side vulnerable vs. remediated code diffs, `[M]` vs. `[SIM]` provenance badges, and live parameterized directory search (`LIKE @SearchPattern ESCAPE '\'`).
  - **Standalone Form (`webform.html`)**: Direct access to the hardened intake form.

---

## Scope Boundaries Across Capstone Activities

SafeVault was developed iteratively across all three Course 8 capstone activities:
- **Activity 1 Scope (Complete)**: Defensive Input Validation, Sanitization, Parameterized SQLite Queries (SQLi prevention), and Automated NUnit Vulnerability Tests (8 tests).
- **Activity 2 Scope (Complete)**: User Authentication, BCrypt Password Hashing with 128-bit Salts, HMAC-SHA256 Signed Session Tokens, Role-Based Access Control (`Admin`, `Auditor`, `User`), and Automated Auth/RBAC NUnit Security Tests (10 additional tests, 18 cumulative).
- **Activity 3 Scope (Complete)**: Security Vulnerability Debugging & Remediation Audit (`V1`–`V4` `[M]` and `S1`–`S2` `[SIM]`), Wildcard-Safe Parameterized Directory Search, Expanded NUnit Regression Suite (10 additional tests, 28 cumulative), Interactive Cycle 7 Audit Workspace, and Final Capstone Evaluation Summary (Criteria C4, C5 & C6).

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
├── cycle7-debug.html
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
│       │   ├── PasswordHasher.cs
│       │   └── SecurityAuditService.cs
│       ├── Program.cs
│       └── SafeVault.csproj
└── Tests/
    ├── TestAuthAndRbac.cs
    ├── TestInputValidation.cs
    ├── TestVulnerabilityRemediation.cs
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

### Run Security, RBAC & Remediation Tests
```bash
dotnet test SafeVault.sln -c Release --logger "console;verbosity=detailed"
```

All 28 unit tests execute against an isolated in-memory SQLite database (`0` warnings, `0` errors) to verify input validation, SQLi prevention, XSS encoding, BCrypt password hashing, login authentication, RBAC route enforcement, and Activity 3 vulnerability remediations.

---

## AI Assistance Disclosure & Activity 3 Capstone Security Summary (Criterion C6)

*This section provides transparent disclosure of tool usage and presents the final Activity 3 debugging and remediation summary in accordance with the capstone evaluation criteria (Criteria C2, C3, C4, C5, and C6).*

### 1. Cumulative AI Assistance Overview (Activities 1–3)
Across the development and security hardening of SafeVault, an AI environment was utilized as a defensive engineering aid:
1. **Input Validation and Sanitization (Criterion C2)**: An AI environment assisted in designing regular expression patterns, regex timeout bounds, and the dual-stage sanitization pipeline (`InputValidator.cs` and `js/safevault.js`) to neutralize Cross-Site Scripting (XSS) vectors across form inputs.
2. **SQL Injection Prevention (Criterion C2 & Criterion C4)**: An AI environment assisted in structuring parameterized `SqliteCommand` queries, verifying `SqliteParameter` bindings (`@Username`, `@Email`, `@PasswordHash`, `@Role`, `@SearchPattern`), and implementing wildcard-escaped `LIKE` searches so user inputs are never concatenated into SQL command text.
3. **Authentication and Role-Based Access Control (Criterion C3)**: An AI environment assisted in implementing the salted BCrypt password hashing service (`PasswordHasher.cs`), constant-time login verification with anti-enumeration fallback (`AuthService.cs`), and HMAC-SHA256 session token issuance and RBAC route enforcement (`AuthorizationService.cs`).
4. **Vulnerability Debugging and Regression Test Formulation (Criteria C4, C5 & C6)**: During Activity 3, the AI environment assisted in auditing the Activities 1–2 codebase for residual edge-case weaknesses, formulating targeted security fixes, and expanding the automated NUnit suite to 28 tests across `Tests/TestInputValidation.cs`, `Tests/TestAuthAndRbac.cs`, and `Tests/TestVulnerabilityRemediation.cs`.

### 2. Activity 3 Vulnerabilities Identified (`[M]` Measured Codebase Findings vs. `[SIM]` Simulated Baselines)
To maintain strict evidence provenance during the Activity 3 audit, findings were categorized into **Measured Codebase Findings (`Identified in Codebase [M]`)**—real edge-case defects diagnosed in the Activities 1–2 files—and **Simulated Exercise Baselines (`Simulated Exercise Baseline [SIM]`)** representing textbook unparameterized/unescaped anti-patterns evaluated side-by-side:

| ID | Provenance Badge | Target Surface | Vulnerability Diagnosed | Remediation Implemented & Verified |
| :--- | :--- | :--- | :--- | :--- |
| **V1** | `Identified in Codebase [M]` | `InputValidator.cs`, `js/safevault.js` | `EmailPattern` (`^[^@\s]+@[^@\s]+\.[^@\s]+$`) permitted angle brackets, quotes, and script fragments in email local-parts (e.g., `"<script>@test.local"` passed `IsValid = true`); `ScriptTagPattern` only stripped `onerror`/`onload`/`onclick` and plain `javascript:`, omitting broader `on*=` attributes, `data:`/`vbscript:` URIs, control-character stripping, and regex timeouts. | Restricted `EmailPattern` to `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`, rejected `<`, `>`, `"`, `'`, `;`, `(`, `)`, `|`, `\`, `` ` ``, stripped ASCII control characters, expanded `ScriptTagPattern` to strip all `\bon[a-z0-9_]+\s*=` handlers and whitespace-obfuscated `javascript:`/`vbscript:`/`data:text/html` schemes, and enforced a `250ms` `RegexTimeout`. Verified by `TestEmailValidation_RejectsEmbeddedXssAndSqlPayloads` and `TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols`. |
| **V2** | `Identified in Codebase [M]` | `UserRepository.cs`, `Program.cs` | `InitializeSchema()` omitted `UNIQUE` on `Username` in SQLite DDL (allowing duplicate intake on `POST /submit`), `EnsureColumnExists()` interpolated column definitions without a static allowlist, `GET /api/users/{username}` lacked pre-query validation, and parameterized wildcard-safe directory search was absent. | Added `UNIQUE` on `Users(Username)` (`idx_users_username`) and `409 Conflict` duplicate checks on `POST /submit`, enforced a static `AllowedSchemaColumns` allowlist in `EnsureColumnExists()`, added username validation on `GET /api/users/{username}`, and implemented `SearchUsersAsync()` using `SqliteParameter("@SearchPattern")` with `LIKE @SearchPattern ESCAPE '\'`. Verified by `TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards`, `TestUniqueUsernameConstraint_PreventsDuplicateIntakeAndRegistration`, and `TestSchemaMigration_RejectsUnwhitelistedColumnIdentifier`. |
| **V3** | `Identified in Codebase [M]` | `AuthorizationService.cs`, `Program.cs` | `IssueSessionToken()` formatted `{userId}|{username}|{role}|{exp}` without rejecting pipe (`|`) delimiters or control characters in `username`, and `Program.cs` omitted defensive HTTP security headers. | Added claim guards in `IssueSessionToken()` and `ValidateSessionToken()` rejecting `|`, control characters, and non-positive user IDs; added HTTP security headers middleware (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`). Verified by `TestSessionToken_RejectsPipeDelimiterInjectionInUsername`. |
| **V4** | `Identified in Codebase [M]` | `PasswordHasher.cs` | `PasswordHasher.MaxWorkFactor` was set to `16` instead of the documented BCrypt upper bound of `31`. | Updated `PasswordHasher.MaxWorkFactor = 31` (`MinWorkFactor = 4`, `MaxWorkFactor = 31`) and verified boundary behavior in `TestPasswordHasher_EnforcesStandardWorkFactorBounds`. |
| **S1** | `Simulated Exercise Baseline [SIM]` | User Lookup & Search Queries | Simulated concatenated SQL query (`"SELECT * FROM Users WHERE Username = '" + input + "'"`) allowing tautologies (`' OR '1'='1`) and stacked commands (`'; DROP TABLE Users; --`) to bypass authentication or dump records. | Contrasted against parameterized `SqliteCommand` and `SqliteParameter` bindings in `UserRepository.cs` and `SecurityAuditService.cs`. Verified by `TestForSQLInjection`, `TestLogin_SqlInjectionPayloads_AreNeutralized`, and `TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards`. |
| **S2** | `Simulated Exercise Baseline [SIM]` | Form & Profile DOM Rendering | Simulated unescaped HTML reflection (`element.innerHTML = rawInput`) allowing `<script>`, `<svg onload=...>`, and inline event handlers to execute arbitrary script in the browser. | Contrasted against `InputValidator.Sanitize()` + `WebUtility.HtmlEncode()` on the server and `textContent` / `escapeHtml()` on the client. Verified by `TestForXSS` and `TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols`. |

### 3. How the AI Environment Assisted in the Debugging Process
1. **Static Surface Inspection & Edge-Case Discovery**: The AI environment assisted in systematically reviewing regular expressions, SQLite schema DDL statements, token serialization formats, and endpoint handlers across the Activities 1–2 codebase. By analyzing each regex character class and string delimiter boundary, the AI environment helped diagnose that `^[^@\s]+@[^@\s]+\.[^@\s]+$` permitted `<script>` and quotes inside email local-parts (`V1`), that `Users(Username)` lacked a runtime `UNIQUE` constraint in `UserRepository.InitializeSchema()` (`V2`), and that pipe-delimited token payloads required explicit delimiter guards (`V3`).
2. **Remediation Pattern Synthesis**: For each diagnosed issue, the AI environment assisted in formulating defense-in-depth fixes: pairing strict allowlist regexes with `250ms` execution timeouts, escaping SQLite `LIKE` wildcards (`%`, `_`, `\`) alongside `SqliteParameter` binding (`LIKE @SearchPattern ESCAPE '\'`), and enforcing a static schema-identifier allowlist on `ALTER TABLE` operations.
3. **Adversarial Regression Test Generation**: Finally, AI assistance was used to design 10 targeted NUnit test methods in `Tests/TestVulnerabilityRemediation.cs` that replay obfuscated XSS vectors (`java\tscript:`, `data:text/html`, `onmouseover=`), SQL injection tautologies, `%` wildcard dumps, duplicate username insertions, unwhitelisted DDL identifiers, and pipe-delimiter token claims, confirming that all 28 automated tests pass with zero regressions.
