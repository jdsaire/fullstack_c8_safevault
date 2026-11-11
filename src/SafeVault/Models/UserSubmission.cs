namespace SafeVault.Models;

public static class VaultRoles
{
    public const string Admin = "Admin";
    public const string Auditor = "Auditor";
    public const string User = "User";

    public static readonly IReadOnlySet<string> AllRoles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Admin,
        Auditor,
        User
    };

    public static bool IsValidRole(string? role) =>
        !string.IsNullOrWhiteSpace(role) && AllRoles.Contains(role.Trim());

    public static string NormalizeRole(string? role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            return User;
        }

        var trimmed = role.Trim();
        if (string.Equals(trimmed, Admin, StringComparison.OrdinalIgnoreCase))
        {
            return Admin;
        }

        if (string.Equals(trimmed, Auditor, StringComparison.OrdinalIgnoreCase))
        {
            return Auditor;
        }

        return User;
    }
}

public record UserSubmission(string? Username, string? Email);

public record UserRecord(int UserId, string Username, string Email);

public record UserAccountRecord(
    int UserId,
    string Username,
    string Email,
    string PasswordHash,
    string Role,
    string CreatedAt
);

public record ValidationResult(
    bool IsValid,
    string? SanitizedUsername,
    string? SanitizedEmail,
    IReadOnlyList<string> Errors
);

public record RegisterUserRequest(
    string? Username,
    string? Email,
    string? Password,
    string? Role = VaultRoles.User
);

public record LoginRequest(
    string? Username,
    string? Password
);

public record RoleUpdateRequest(
    string? NewRole
);

public record HashInspectionResult(
    string Algorithm,
    int WorkFactor,
    string SaltPrefix,
    int HashLength,
    bool IsValidFormat
);

public record AuthResult(
    bool IsAuthenticated,
    int StatusCode,
    string Message,
    int? UserId,
    string? Username,
    string? Email,
    string? Role,
    string? Token,
    IReadOnlyList<string> Errors
);

public record AccessControlResult(
    bool IsAuthorized,
    int StatusCode,
    string Message,
    string Resource,
    string RequiredRoles,
    string? Username,
    string? ActualRole
);

public record VulnerabilityFinding(
    string Id,
    string ProvenanceBadge,
    string Category,
    string TargetSurface,
    string VulnerabilityDescription,
    string RemediationApplied,
    string VerificationTest
);

public record RemediationProbeRequest(
    string? VectorCategory,
    string? Payload
);

public record RemediationProbeResult(
    string VectorCategory,
    string RawPayload,
    string VulnerablePattern,
    string RemediatedPattern,
    bool IsAttackBlocked,
    string SanitizedOrBoundOutput,
    string DefenseVerdict
);

public record SearchUsersResult(
    bool IsValid,
    string Query,
    string EscapedPattern,
    int MatchCount,
    IReadOnlyList<UserRecord> Matches,
    IReadOnlyList<string> Errors
);
