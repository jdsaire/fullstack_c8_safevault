namespace SafeVault.Models;

public record UserSubmission(string? Username, string? Email);

public record UserRecord(int UserId, string Username, string Email);

public record ValidationResult(
    bool IsValid,
    string? SanitizedUsername,
    string? SanitizedEmail,
    IReadOnlyList<string> Errors
);
