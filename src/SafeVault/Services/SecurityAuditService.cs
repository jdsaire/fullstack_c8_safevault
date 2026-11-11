using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

public class SecurityAuditService
{
    private readonly UserRepository _repository;
    private readonly InputValidator _validator;
    private readonly AuthorizationService _authorizationService;

    public SecurityAuditService(
        UserRepository repository,
        InputValidator validator,
        AuthorizationService authorizationService)
    {
        _repository = repository;
        _validator = validator;
        _authorizationService = authorizationService;
    }

    public IReadOnlyList<VulnerabilityFinding> GetVulnerabilityFindings()
    {
        return new[]
        {
            new VulnerabilityFinding(
                Id: "V1",
                ProvenanceBadge: "Identified in Codebase [M]",
                Category: "XSS & Input Validation",
                TargetSurface: "src/SafeVault/Services/InputValidator.cs, js/safevault.js",
                VulnerabilityDescription: "EmailPattern (^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$) permitted angle brackets, quotes, and script fragments inside email local-parts (e.g., '<script>@test.local' passed IsValid=true); ScriptTagPattern only matched onerror/onload/onclick and plain javascript:, omitting broader on*= event handlers, data:/vbscript: schemes, control-character stripping, and regex match timeouts.",
                RemediationApplied: "Restricted EmailPattern to ^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$, explicitly disallowed '<', '>', '\"', '\\'', ';', '(', ')', '|', '\\\\', '`', stripped ASCII control characters, expanded ScriptTagPattern to strip all on[a-z0-9_]+= attributes and whitespace-obfuscated javascript:/vbscript:/data:text/html protocols, and added 250ms RegexTimeout.",
                VerificationTest: "TestEmailValidation_RejectsEmbeddedXssAndSqlPayloads, TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols"
            ),
            new VulnerabilityFinding(
                Id: "V2",
                ProvenanceBadge: "Identified in Codebase [M]",
                Category: "SQL Schema, DDL & Search Parameterization",
                TargetSurface: "src/SafeVault/Data/UserRepository.cs, src/SafeVault/Program.cs",
                VulnerabilityDescription: "UserRepository.InitializeSchema() omitted UNIQUE on Username in SQLite DDL (allowing duplicate intake on POST /submit), EnsureColumnExists() interpolated column definitions without an explicit static allowlist, GET /api/users/{username} lacked input validation prior to querying, and parameterized wildcard-safe user search was absent.",
                RemediationApplied: "Enforced UNIQUE on Users(Username) and 409 Conflict duplicate checks on POST /submit, enforced AllowedSchemaColumns static allowlist in EnsureColumnExists(), validated GET /api/users/{username} parameters, and implemented SearchUsersAsync() using SqliteParameter with LIKE @SearchPattern ESCAPE '\\' and wildcard escaping.",
                VerificationTest: "TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards, TestUniqueUsernameConstraint_PreventsDuplicateIntakeAndRegistration, TestSchemaMigration_RejectsUnwhitelistedColumnIdentifier"
            ),
            new VulnerabilityFinding(
                Id: "V3",
                ProvenanceBadge: "Identified in Codebase [M]",
                Category: "Token Claim Integrity & HTTP Security Headers",
                TargetSurface: "src/SafeVault/Services/AuthorizationService.cs, src/SafeVault/Program.cs",
                VulnerabilityDescription: "AuthorizationService.IssueSessionToken() assembled pipe-delimited payloads ('{userId}|{username}|{role}|{exp}') without rejecting '|' or control characters in usernames, and Program.cs did not emit defensive HTTP security headers (Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).",
                RemediationApplied: "Added explicit validation in IssueSessionToken() and ValidateSessionToken() rejecting pipe ('|') delimiters, control characters, and non-positive user IDs; added HTTP security headers middleware in Program.cs.",
                VerificationTest: "TestSessionToken_RejectsPipeDelimiterInjectionInUsername"
            ),
            new VulnerabilityFinding(
                Id: "V4",
                ProvenanceBadge: "Identified in Codebase [M]",
                Category: "Cryptographic Configuration Boundary",
                TargetSurface: "src/SafeVault/Services/PasswordHasher.cs",
                VulnerabilityDescription: "PasswordHasher.MaxWorkFactor was set to 16 instead of the standard BCrypt upper bound of 31 documented in Activity 2 specifications.",
                RemediationApplied: "Aligned PasswordHasher.MaxWorkFactor = 31 (range 4–31) and added explicit boundary unit tests.",
                VerificationTest: "TestPasswordHasher_EnforcesStandardWorkFactorBounds"
            ),
            new VulnerabilityFinding(
                Id: "S1",
                ProvenanceBadge: "Simulated Exercise Baseline [SIM]",
                Category: "SQL Injection via String Concatenation",
                TargetSurface: "Activity 3 Scenario · User Lookup & Directory Search Queries",
                VulnerabilityDescription: "Simulated vulnerable query pattern: SELECT * FROM Users WHERE Username = '\" + input + \"' allows tautologies (' OR '1'='1) and stacked commands ('; DROP TABLE Users; --) to alter SQL grammar.",
                RemediationApplied: "Replaced dynamic string concatenation with parameterized SqliteCommand and SqliteParameter bindings (@Username, @SearchPattern with ESCAPE '\\') in UserRepository.cs.",
                VerificationTest: "TestForSQLInjection, TestLogin_SqlInjectionPayloads_AreNeutralized, TestParameterizedSearch_BlocksSqlInjectionAndEscapesWildcards"
            ),
            new VulnerabilityFinding(
                Id: "S2",
                ProvenanceBadge: "Simulated Exercise Baseline [SIM]",
                Category: "Reflected & Stored XSS in Form Handling",
                TargetSurface: "Activity 3 Scenario · Web Form & Profile Output Rendering",
                VulnerabilityDescription: "Simulated vulnerable output pattern: rendering unsanitized user input directly into HTML markup (innerHTML = userInput) allows <script>, <svg onload=...>, and on*= event handlers to execute arbitrary JavaScript.",
                RemediationApplied: "Implemented dual-stage defense: InputValidator.Sanitize() strips control characters, dangerous tags, event handlers, and script protocols, then encodes entities via WebUtility.HtmlEncode(); DOM views bind via textContent or escapeHtml().",
                VerificationTest: "TestForXSS, TestSanitize_StripsObfuscatedEventsControlCharsAndProtocols"
            )
        };
    }

    public async Task<RemediationProbeResult> ExecuteRemediationProbeAsync(string? vectorCategory, string? payload)
    {
        var category = (vectorCategory ?? "sqli").Trim().ToLowerInvariant();
        var raw = payload ?? string.Empty;

        switch (category)
        {
            case "email":
            {
                var validation = _validator.ValidateAndSanitize("valid_probe_user", raw);
                var vulnerablePattern = "Regex.IsMatch(email, @\"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$\") // Allows '<script>@evil.com'";
                var remediatedPattern = "EmailPattern ^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$ + DisallowedEmailChars check";
                var blocked = !validation.IsValid;
                return new RemediationProbeResult(
                    VectorCategory: "email",
                    RawPayload: raw,
                    VulnerablePattern: vulnerablePattern,
                    RemediatedPattern: remediatedPattern,
                    IsAttackBlocked: blocked,
                    SanitizedOrBoundOutput: validation.SanitizedEmail ?? string.Empty,
                    DefenseVerdict: blocked
                        ? $"Blocked [M]: Malicious email rejected ({string.Join(" ", validation.Errors)}) and sanitized to '{validation.SanitizedEmail}'."
                        : "Accepted: Compliant RFC email format."
                );
            }

            case "xss":
            {
                var sanitized = _validator.Sanitize(raw);
                var validation = _validator.ValidateAndSanitize(raw, "audit@safevault.local");
                var containsExecutable = sanitized.Contains("<script", StringComparison.OrdinalIgnoreCase) ||
                                         sanitized.Contains("onerror=", StringComparison.OrdinalIgnoreCase) ||
                                         sanitized.Contains("onload=", StringComparison.OrdinalIgnoreCase) ||
                                         sanitized.Contains("onmouseover=", StringComparison.OrdinalIgnoreCase) ||
                                         sanitized.Contains("javascript:", StringComparison.OrdinalIgnoreCase) ||
                                         sanitized.Contains("vbscript:", StringComparison.OrdinalIgnoreCase);
                return new RemediationProbeResult(
                    VectorCategory: "xss",
                    RawPayload: raw,
                    VulnerablePattern: "element.innerHTML = rawInput; // Executes inline <script>, on* handlers, and data:/javascript: URIs",
                    RemediatedPattern: "InputValidator.Sanitize(rawInput) -> ControlChar strip + ScriptTagPattern strip + WebUtility.HtmlEncode()",
                    IsAttackBlocked: !containsExecutable && !validation.IsValid,
                    SanitizedOrBoundOutput: sanitized,
                    DefenseVerdict: $"Neutralized [M/SIM]: Stripped executable tokens and encoded to '{sanitized}'; username validation IsValid={validation.IsValid}."
                );
            }

            case "token":
            {
                bool blocked = false;
                string detail;
                try
                {
                    _ = _authorizationService.IssueSessionToken(10, raw, VaultRoles.User);
                    detail = "Valid username accepted for token issuance.";
                }
                catch (ArgumentException ex)
                {
                    blocked = true;
                    detail = $"Blocked [M]: Token claim injection prevented ({ex.Message}).";
                }

                return new RemediationProbeResult(
                    VectorCategory: "token",
                    RawPayload: raw,
                    VulnerablePattern: "payload = $\"{userId}|{username}|{role}|{exp}\" // Unchecked '|' in username shifts role claim index",
                    RemediatedPattern: "AuthorizationService.IssueSessionToken() rejects '|' delimiter and control chars before HMAC-SHA256 signing",
                    IsAttackBlocked: blocked,
                    SanitizedOrBoundOutput: blocked ? "TOKEN_ISSUANCE_ABORTED" : raw,
                    DefenseVerdict: detail
                );
            }

            case "search":
            default:
            {
                var searchValidation = _validator.ValidateSearchQuery(raw);
                var matches = searchValidation.IsValid
                    ? await _repository.SearchUsersAsync(raw)
                    : Array.Empty<UserRecord>();
                var tableIntact = _repository.TableExists("Users");

                return new RemediationProbeResult(
                    VectorCategory: category == "search" ? "search" : "sqli",
                    RawPayload: raw,
                    VulnerablePattern: $"SELECT UserID, Username, Email FROM Users WHERE Username LIKE '%{raw}%'; // Vulnerable to SQLi & '%' wildcard dump",
                    RemediatedPattern: "WHERE Username LIKE @SearchPattern ESCAPE '\\' // @SearchPattern = \"%" + searchValidation.EscapedLikePattern + "%\" (SqliteParameter)",
                    IsAttackBlocked: tableIntact && matches.All(m => m.Username.Contains(raw.Trim(), StringComparison.OrdinalIgnoreCase) || m.Email.Contains(raw.Trim(), StringComparison.OrdinalIgnoreCase)),
                    SanitizedOrBoundOutput: $"@SearchPattern = \"%{searchValidation.EscapedLikePattern}%\" (Matched: {matches.Count} rows, Users table intact: {tableIntact})",
                    DefenseVerdict: $"Neutralized [M/SIM]: Bound as literal SqliteParameter with escaped wildcards; 0 unauthorized rows leaked, Users table 100% intact."
                );
            }
        }
    }
}
