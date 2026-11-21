# SafeVault

**Defense-in-Depth Web Application & Security Verification Lab**  
*Microsoft Full Stack Developer Specialization — Course 8: Security and Authentication Capstone*

SafeVault is a security-focused web application built to protect user identities, cryptographic credentials, and role-restricted records against common web application threats—including SQL Injection (SQLi), Cross-Site Scripting (XSS), credential enumeration, and broken access control.

**Live Interactive Workspace:** [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/)  
*(Explore all 7 interactive security verification cycles directly in the browser via static client simulation `[SIM]`, or run the full ASP.NET Core 8.0 + SQLite backend locally `[M]`.)*

---

## Executive Security Posture Snapshot

| Dimension | Verified Outcome | Evidence |
|---|---|---|
| **Vulnerability Remediation** | **4** codebase defects diagnosed & resolved (`V1`–`V4`) + **2** textbook anti-patterns contrasted (`S1`–`S2`) | `[M]` / `[SIM]` |
| **Automated Test Coverage** | **28 / 28** NUnit security assertions passing (`0` warnings, `0` errors, `6.83 s` in-memory SQLite) | `[M]` |
| **Access Control Model** | **3** least-privilege role tiers (`Admin`, `Auditor`, `User`) with HMAC-SHA256 signed bearer tokens | `[M]` |
| **Credential Protection** | Salted **BCrypt** hashing (work factor `12`, unique 128-bit salts) + constant-time anti-enumeration login | `[M]` |
| **Verification Surfaces** | **1** Executive Hub + **7** interactive security cycles + **3** rubric-mapped completion reports | `[SIM]` / `[M]` |

---

## Core Security Architecture & Risk Reduction

SafeVault enforces defense-in-depth across four architectural pillars, pairing each technical control with the business risk it reduces:

### 1. Perimeter Input Hygiene & XSS Defense
- **Risk Addressed:** Malicious script injection, DOM hijacking, and Regular Expression Denial of Service (ReDoS) through untrusted form and API inputs.
- **Architectural Controls:** Dual-boundary allowlist validation across browser forms (`webform.html`, `cycle1-intake.html`) and server-side validation (`src/SafeVault/Services/InputValidator.cs`). All untrusted inputs pass through control-character stripping, broad inline event and executable URI removal, HTML entity encoding, and bounded `250ms` regex timeouts.

### 2. Injection-Proof Data Access & Safe Directory Search
- **Risk Addressed:** Authentication bypass, unauthorized data extraction, duplicate account collisions, and wildcard-based directory dumping.
- **Architectural Controls:** Every database operation in `src/SafeVault/Data/UserRepository.cs` uses strictly parameterized SQLite commands (`SqliteParameter`) so user input is never concatenated into SQL syntax. Directory search explicitly escapes wildcard characters (`\`, `%`, `_`) via `LIKE @SearchPattern ESCAPE '\'`, database DDL enforces a `UNIQUE` username index (`409 Conflict` on duplicates) and role `CHECK` constraints, and schema migration helpers validate identifiers against a static allowlist.

### 3. Cryptographic Identity & Anti-Enumeration
- **Risk Addressed:** Offline credential cracking from leaked password hashes and timing-based username discovery.
- **Architectural Controls:** Passwords are never stored or logged in plaintext. `src/SafeVault/Services/PasswordHasher.cs` applies `BCrypt.Net-Next` with a default cost factor of `12` (4,096 key-expansion rounds), bounded standard work-factor limits (`4`–`31`), and per-user 128-bit random salts. `src/SafeVault/Services/AuthService.cs` verifies unknown usernames against a precomputed dummy BCrypt hash and returns uniform failure responses to mitigate timing and response-based account enumeration.

### 4. Least-Privilege Access Control & Browser Hardening
- **Risk Addressed:** Privilege escalation, forged session tokens, clickjacking, and MIME-sniffing attacks.
- **Architectural Controls:** `src/SafeVault/Services/AuthorizationService.cs` issues HMAC-SHA256 signed bearer tokens verified in constant time, rejecting delimiter (`|`) and control-character claim injection during both issuance and parsing. Minimal API routes in `src/SafeVault/Program.cs` enforce strict role separation (`Admin`, `Auditor`, `User`), while global HTTP middleware emits `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.

---

## Automated Security Verification Coverage (`28 / 28` Passing `[M]`)

All automated assertions execute against an isolated in-memory SQLite database via `dotnet test SafeVault.sln -c Release`:

| Coverage Card | Fixture | Tests | Security Scenarios Verified |
|---|---|---:|---|
| **1. Input Validation & Injection Defense** | [`Tests/TestInputValidation.cs`](Tests/TestInputValidation.cs) | **8** | SQLi tautologies, stacked `DROP TABLE` queries, inline comments, `UNION SELECT` payloads, `<script>` / event-handler XSS neutralization, and username/email boundary rules. |
| **2. Authentication & RBAC Enforcement** | [`Tests/TestAuthAndRbac.cs`](Tests/TestAuthAndRbac.cs) | **10** | Unique per-user BCrypt salting, valid login token issuance, wrong-password and unknown-user anti-enumeration, SQLi-in-login neutralization, role-matrix access (`Admin` / `Auditor` / `User`), tampered token rejection (`401`), and weak-password rejection. |
| **3. Vulnerability Remediation & Regression** | [`Tests/TestVulnerabilityRemediation.cs`](Tests/TestVulnerabilityRemediation.cs) | **10** | Embedded XSS in email local-parts, obfuscated `on*=` and URI protocol stripping, wildcard-escaped `LIKE` search, unique username enforcement, DDL identifier allowlisting, pipe-delimiter token injection, BCrypt work-factor bounds, null-byte/oversized payload rejection, `[M]`/`[SIM]` audit separation, and full end-to-end regression. |

---

## Interactive Verification Workspace (`7` Cycles)

The live site ([https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/)) modularizes SafeVault into dedicated, idle-state verification pages backed by client-side simulation fallback (`[SIM]`) when hosted statically and live ASP.NET Core endpoints (`[M]`) when run locally:

| Workspace | Page | Focus Area |
|---|---|---|
| **Executive Hub** | [`index.html`](index.html) | Mission overview, cumulative architecture summary, and sequential navigation across Cycles 1–7. |
| **Cycle 1** | [`cycle1-intake.html`](cycle1-intake.html) | Validated user intake, real-time input hygiene checks, and relational record view. |
| **Cycle 2** | [`cycle2-sqli.html`](cycle2-sqli.html) | SQL injection attack testing and parameterized `SqliteParameter` inspection. |
| **Cycle 3** | [`cycle3-xss.html`](cycle3-xss.html) | Cross-Site Scripting defense with dual-stage sanitization and HTML entity encoding. |
| **Cycle 4** | [`cycle4-tests.html`](cycle4-tests.html) | Interactive 28-assertion security test suite runner. |
| **Cycle 5** | [`cycle5-auth.html`](cycle5-auth.html) | BCrypt hash structure inspector (`$2a$12$...`) and credential authentication verifier. |
| **Cycle 6** | [`cycle6-rbac.html`](cycle6-rbac.html) | Role-Based Access Control simulator across `Admin`, `Auditor`, `User`, `Guest`, and tampered tokens. |
| **Cycle 7** | [`cycle7-debug.html`](cycle7-debug.html) | Activity 3 vulnerability audit ledger (`[M]` vs. `[SIM]`), before/after code diffs, and wildcard-safe directory search. |
| **Standalone Form** | [`webform.html`](webform.html) | Direct access to the hardened intake form. |

---

## Repository Structure & Architecture Map

SafeVault keeps static HTML entrypoints at the repository root so GitHub Pages serves directly from `main /` with zero broken paths, while the ASP.NET Core backend (`Program.cs`) serves the same root assets locally alongside its Minimal API endpoints:

| Layer | Path | Purpose |
|---|---|---|
| **Static Demo Surface** | `index.html`, `cycle1–7`, `webform.html`, `css/`, `js/` | GitHub Pages root (`[SIM]` fallback) & local ASP.NET Core UI |
| **ASP.NET Core Backend** | `src/SafeVault/` (`Data/`, `Models/`, `Services/`, `Program.cs`) | .NET 8 Minimal API, SQLite repository, auth, RBAC, and audit services (`[M]`) |
| **Automated Test Suite** | `Tests/` (`TestInputValidation.cs`, `TestAuthAndRbac.cs`, `TestVulnerabilityRemediation.cs`) | 28 NUnit security and regression assertions (`[M]`) |
| **Capstone Documentation** | `README.md`, [`REFLECTION.md`](REFLECTION.md), [`docs/reports/`](docs/reports/README.md) | Executive overview, extended reflection, and rubric-mapped activity reports |

```text
├── .gitignore
├── .nojekyll
├── README.md
├── REFLECTION.md
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
│       ├── ACTIVITY-3-COMPLETION-REPORT.md
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

## Quick Start (Build & Verification)

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build & Run Automated Security Suite
```bash
dotnet build SafeVault.sln -c Release
dotnet test SafeVault.sln -c Release --logger "console;verbosity=detailed"
```

### Run Local ASP.NET Core Server
```bash
dotnet run --project src/SafeVault/SafeVault.csproj
```

---

## Tooling Disclosure & Activity 3 Security Audit Summary (Criterion C6)

*This section provides transparent disclosure of end-to-end tooling usage and summarizes the Activity 3 vulnerability audit across the capstone evaluation criteria (C2–C6). For the extended capstone reflection and detailed activity-by-activity audit trails, see [`REFLECTION.md`](REFLECTION.md) and [`docs/reports/README.md`](docs/reports/README.md).*

### 1. End-to-End Tooling Disclosure (Activities 1–3)
**Antigravity** was used as the sole end-to-end tooling platform across all three capstone activities:
- **Input Validation & SQLi Prevention (Criterion C2):** Antigravity assisted in designing allowlist validation rules, regex timeouts, dual-stage XSS sanitization, and parameterized `SqliteParameter` queries across `InputValidator.cs`, `UserRepository.cs`, and `js/safevault.js`.
- **Authentication & RBAC (Criterion C3):** Antigravity assisted in implementing salted BCrypt hashing (`PasswordHasher.cs`), constant-time anti-enumeration authentication (`AuthService.cs`), and HMAC-SHA256 bearer tokens with `Admin`/`Auditor`/`User` role gates (`AuthorizationService.cs`, `Program.cs`).
- **Vulnerability Debugging & Regression Testing (Criteria C4, C5 & C6):** Antigravity assisted in auditing the Activities 1–2 codebase for residual edge-case weaknesses, formulating targeted defense-in-depth remediations, and expanding the automated NUnit suite to 28 passing security assertions.

### 2. Activity 3 Vulnerability Audit Ledger (`[M]` Measured vs. `[SIM]` Baseline)

| ID | Provenance | Target Surface | Risk Diagnosed | Remediation Implemented & Verified |
|---|---|---|---|---|
| **V1** | `Identified in Codebase [M]` | `InputValidator.cs`, `js/safevault.js` | Permissive email regex allowed angle brackets and quotes in local-parts; sanitizer omitted broad `on*=` attributes, obfuscated URI schemes, control characters, and regex timeouts. | Enforced strict email allowlist, dangerous-character and control-character rejection, broad `on*=` and `javascript:`/`vbscript:`/`data:text/html` stripping, HTML encoding, and `250ms` `RegexTimeout`. Verified by 2 dedicated NUnit tests. |
| **V2** | `Identified in Codebase [M]` | `UserRepository.cs`, `Program.cs` | Missing runtime `UNIQUE` constraint on `Username`, unwhitelisted DDL column helper, unvalidated lookup parameter, and missing wildcard-safe directory search. | Added `UNIQUE` username index with `409 Conflict` duplicate guard, static `AllowedSchemaColumns` DDL allowlist, pre-query username validation, and parameterized `LIKE @SearchPattern ESCAPE '\'` search. Verified by 3 dedicated NUnit tests. |
| **V3** | `Identified in Codebase [M]` | `AuthorizationService.cs`, `Program.cs` | Pipe-delimited session tokens lacked explicit `|` and control-character guards; HTTP responses omitted defensive browser security headers. | Added claim-delimiter and control-character guards on token issuance and validation; added global `CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy` headers. Verified by dedicated token-injection test. |
| **V4** | `Identified in Codebase [M]` | `PasswordHasher.cs` | BCrypt `MaxWorkFactor` was capped at `16` instead of the documented standard upper bound of `31`. | Aligned work-factor bounds to `4`–`31` (default `12`) and verified boundary enforcement via NUnit test. |
| **S1** | `Simulated Baseline [SIM]` | User Lookup & Search | Textbook string-concatenated SQL query vulnerable to tautologies and stacked commands. | Contrasted directly against parameterized `SqliteCommand` bindings in `UserRepository.cs`, `SecurityAuditService.cs`, and Cycle 2 / Cycle 7 workspaces. |
| **S2** | `Simulated Baseline [SIM]` | Form & Profile DOM | Textbook unescaped `innerHTML` reflection allowing arbitrary script execution. | Contrasted directly against server-side `Sanitize()` + `WebUtility.HtmlEncode()` and client-side `textContent` / `escapeHtml()` in Cycle 3 / Cycle 7 workspaces. |
