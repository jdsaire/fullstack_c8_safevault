# SafeVault Capstone Reflection

**Project:** SafeVault — Secure Web Application & Defense-in-Depth Verification Lab  
**Program:** Microsoft Full Stack Developer Specialization · Course 8: *Security and Authentication*  
**Author:** Juan Diego S. (`jdsaire`)  
**Repository:** [https://github.com/jdsaire/fullstack_c8_safevault](https://github.com/jdsaire/fullstack_c8_safevault)  
**Live Interactive Workspace:** [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/)

---

## 1. How Antigravity Assisted Across the Capstone

Antigravity served as the sole end-to-end tooling platform across all three capstone activities—from initial security scaffolding through cryptographic authentication, static vulnerability auditing, and automated regression testing:

- **Activity 1 — Input Validation & SQL Injection Defense:** Antigravity assisted in designing the dual-boundary validation architecture across the intake form (`webform.html`, `cycle1-intake.html`) and server-side `InputValidator.cs`, structuring parameterized SQLite commands (`SqliteParameter`) in `UserRepository.cs`, and building the initial 8-test NUnit fixture (`Tests/TestInputValidation.cs`) targeting SQLi tautologies, stacked queries, and XSS payloads.
- **Activity 2 — Cryptographic Authentication & RBAC:** Antigravity assisted in implementing salted BCrypt password hashing (`PasswordHasher.cs`, work factor 12 with unique 128-bit salts), constant-time login verification with dummy-hash anti-enumeration (`AuthService.cs`), HMAC-SHA256 signed bearer tokens and role-based route gates (`Admin`, `Auditor`, `User`) in `AuthorizationService.cs` and `Program.cs`, and 10 NUnit authentication/RBAC tests (`Tests/TestAuthAndRbac.cs`).
- **Activity 3 — Security Debugging, Remediation & Regression Testing:** Antigravity assisted in auditing the Activities 1–2 codebase to surface four real residual edge-case weaknesses (`V1`–`V4` `[M]`), formulating defense-in-depth patches, adding wildcard-safe parameterized search (`LIKE @SearchPattern ESCAPE '\'`), expanding the automated NUnit suite to 28 tests (`Tests/TestVulnerabilityRemediation.cs`), and refining all 7 interactive browser workspaces to clean idle arrival states.

---

## 2. Challenges Identified and Fixes Applied

A disciplined audit of the codebase separated **measured codebase defects (`[M]`)** from **simulated textbook anti-patterns (`[SIM]`)**:

1. **Permissive Email Pattern & Obfuscated XSS Vectors (`V1` `[M]`):**
   - *Challenge:* The initial email regex allowed angle brackets and quotes in the local-part (e.g., `"<script>@test.local"`), and sanitization only stripped a narrow list of inline event handlers without regex execution timeouts.
   - *Fix:* Hardened the email allowlist regex, added an explicit dangerous-character and ASCII control-character blocklist, expanded sanitization to strip all `on*=` attributes plus whitespace-obfuscated `javascript:`/`vbscript:`/`data:text/html` URIs, applied HTML entity encoding, and enforced a `250ms` `RegexTimeout` to mitigate ReDoS.
2. **Schema Uniqueness, DDL Interpolation & Wildcard Search (`V2` `[M]`):**
   - *Challenge:* Runtime SQLite initialization lacked a `UNIQUE` constraint on `Users(Username)`, migration column helpers interpolated identifiers without an allowlist, and directory search needed wildcard protection.
   - *Fix:* Enforced `UNIQUE` on `Username` (`idx_users_username`) with `409 Conflict` duplicate handling, introduced a static `AllowedSchemaColumns` allowlist for DDL operations, validated `GET /api/users/{username}` inputs before querying, and implemented parameterized `LIKE @SearchPattern ESCAPE '\'` search with explicit wildcard escaping (`\`, `%`, `_`).
3. **Token Claim Delimiter Injection & Missing HTTP Security Headers (`V3` `[M]`):**
   - *Challenge:* Pipe-delimited session token payloads (`userId|username|role|exp`) did not explicitly reject `|` or control characters in usernames, and HTTP responses lacked browser hardening headers.
   - *Fix:* Added claim-delimiter and control-character guards on both token issuance and validation, paired with `CryptographicOperations.FixedTimeEquals` signature verification and global security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`).
4. **Cryptographic Work Factor Bounds (`V4` `[M]`):**
   - *Challenge:* `PasswordHasher.MaxWorkFactor` was capped at `16` rather than the documented BCrypt upper bound of `31`.
   - *Fix:* Aligned bounds to `MinWorkFactor = 4` and `MaxWorkFactor = 31` while maintaining a secure default cost factor of `12`.
5. **Interactive Workspace Hygiene (`[SIM]` Surface):**
   - *Challenge:* Early iterations prefilled attack payloads and auto-ran diagnostics on page load, blurring the line between live user testing and pre-canned output.
   - *Fix:* Normalized all 7 verification cycles (`cycle1-intake.html` through `cycle7-debug.html`) to arrive in an explicit `Idle` state with empty inputs and click-to-populate presets that wait for deliberate user submission.

---

## 3. What I Learned

- **Defense-in-depth requires auditing your own "secure" code:** Even after applying parameterized queries and baseline sanitization in Activity 1, a structured second-pass audit in Activity 3 uncovered subtle boundary bugs (email local-part XSS, unescaped `LIKE` wildcards, pipe delimiters in signed tokens, and missing HTTP headers). Security is a continuous verification loop, not a one-time checklist.
- **Keep evidence provenance explicit (`[M]` vs. `[SIM]`):** Separating measured `.NET 8` / NUnit execution from browser-side static fallback simulations prevents overclaiming backend capabilities on GitHub Pages while still giving reviewers an interactive way to inspect every security control.
- **Iterative verification beats monolithic generation:** Pairing small, single-purpose commits with automated NUnit regression tests and headless browser checks caught defects immediately and kept every pull request clean (`0` build warnings, `0` regressions).
- **Least privilege applies across layers:** Enforcing role gates (`Admin`, `Auditor`, `User`), constant-time authentication with dummy-hash fallback, and strict database constraints together ensures no single bypassed check compromises the vault.

---

## 4. Defensive Validation Summary

- **Automated Backend Suite (`[M]`):** `dotnet build SafeVault.sln -c Release` and `dotnet test SafeVault.sln -c Release` passed **28/28 NUnit tests** (`0` warnings, `0` errors, `6.83 s`) across `TestInputValidation.cs` (8), `TestAuthAndRbac.cs` (10), and `TestVulnerabilityRemediation.cs` (10).
- **Interactive Verification Hub (`[SIM]` Fallback):** Verified all 9 static pages (`index.html`, `cycle1-intake.html` through `cycle7-debug.html`, and `webform.html`) in headless Chrome with `0` console errors and clean `Idle` arrival states.
- **Audit Trail:** Full rubric-mapped completion reports for Activities 1, 2, and 3 are archived in [`docs/reports/`](docs/reports/README.md).
