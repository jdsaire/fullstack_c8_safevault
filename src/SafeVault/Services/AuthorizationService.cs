using System.Security.Cryptography;
using System.Text;
using SafeVault.Models;

namespace SafeVault.Services;

public class AuthorizationService
{
    private readonly byte[] _signingKey;
    private readonly TimeSpan _tokenLifetime;

    public AuthorizationService(byte[]? signingKey = null, TimeSpan? tokenLifetime = null)
    {
        if (signingKey is { Length: >= 32 })
        {
            _signingKey = signingKey;
        }
        else
        {
            _signingKey = RandomNumberGenerator.GetBytes(32);
        }

        _tokenLifetime = tokenLifetime ?? TimeSpan.FromHours(2);
    }

    public string IssueSessionToken(UserAccountRecord account)
    {
        return IssueSessionToken(account.UserId, account.Username, account.Role);
    }

    public string IssueSessionToken(int userId, string username, string role)
    {
        var normalizedRole = VaultRoles.NormalizeRole(role);
        var expiresAtUnix = DateTimeOffset.UtcNow.Add(_tokenLifetime).ToUnixTimeSeconds();
        var payload = $"{userId}|{username}|{normalizedRole}|{expiresAtUnix}";
        var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var signatureBase64 = ComputeSignature(payloadBase64);

        return $"{payloadBase64}.{signatureBase64}";
    }

    public (bool IsValid, int UserId, string? Username, string? Role) ValidateSessionToken(string? rawToken)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return (false, 0, null, null);
        }

        var token = rawToken.Trim();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            token = token["Bearer ".Length..].Trim();
        }

        var parts = token.Split('.');
        if (parts.Length != 2)
        {
            return (false, 0, null, null);
        }

        var payloadBase64 = parts[0];
        var providedSignature = parts[1];
        var expectedSignature = ComputeSignature(payloadBase64);

        var providedBytes = Encoding.UTF8.GetBytes(providedSignature);
        var expectedBytes = Encoding.UTF8.GetBytes(expectedSignature);

        if (!CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes))
        {
            return (false, 0, null, null);
        }

        try
        {
            var decodedPayload = Encoding.UTF8.GetString(Base64UrlDecode(payloadBase64));
            var fields = decodedPayload.Split('|');
            if (fields.Length != 4)
            {
                return (false, 0, null, null);
            }

            if (!int.TryParse(fields[0], out var userId))
            {
                return (false, 0, null, null);
            }

            var username = fields[1];
            var role = fields[2];

            if (!long.TryParse(fields[3], out var expiresAtUnix))
            {
                return (false, 0, null, null);
            }

            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiresAtUnix)
            {
                return (false, 0, null, null);
            }

            if (!VaultRoles.IsValidRole(role))
            {
                return (false, 0, null, null);
            }

            return (true, userId, username, VaultRoles.NormalizeRole(role));
        }
        catch
        {
            return (false, 0, null, null);
        }
    }

    public AccessControlResult AuthorizeByToken(string? token, string resource, params string[] allowedRoles)
    {
        var requiredRolesDisplay = string.Join(", ", allowedRoles);
        var (isValid, _, username, role) = ValidateSessionToken(token);

        if (!isValid || string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(role))
        {
            return new AccessControlResult(
                IsAuthorized: false,
                StatusCode: 401,
                Message: "Authentication required: missing, expired, or invalid session token.",
                Resource: resource,
                RequiredRoles: requiredRolesDisplay,
                Username: null,
                ActualRole: null
            );
        }

        return AuthorizeByRole(username, role, resource, allowedRoles);
    }

    public AccessControlResult AuthorizeByRole(
        string? username,
        string? actualRole,
        string resource,
        params string[] allowedRoles)
    {
        var requiredRolesDisplay = string.Join(", ", allowedRoles);

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(actualRole))
        {
            return new AccessControlResult(
                IsAuthorized: false,
                StatusCode: 401,
                Message: "Authentication required: user identity or role is missing.",
                Resource: resource,
                RequiredRoles: requiredRolesDisplay,
                Username: null,
                ActualRole: null
            );
        }

        var trimmedRole = actualRole.Trim();
        if (!VaultRoles.IsValidRole(trimmedRole))
        {
            return new AccessControlResult(
                IsAuthorized: false,
                StatusCode: 403,
                Message: $"Access denied: unrecognized role '{trimmedRole}'.",
                Resource: resource,
                RequiredRoles: requiredRolesDisplay,
                Username: username,
                ActualRole: trimmedRole
            );
        }

        var normalizedRole = VaultRoles.NormalizeRole(trimmedRole);
        var isPermitted = allowedRoles.Any(r =>
            string.Equals(r, normalizedRole, StringComparison.OrdinalIgnoreCase));

        if (!isPermitted)
        {
            return new AccessControlResult(
                IsAuthorized: false,
                StatusCode: 403,
                Message: $"Access denied: role '{normalizedRole}' cannot access '{resource}'. Required: {requiredRolesDisplay}.",
                Resource: resource,
                RequiredRoles: requiredRolesDisplay,
                Username: username,
                ActualRole: normalizedRole
            );
        }

        return new AccessControlResult(
            IsAuthorized: true,
            StatusCode: 200,
            Message: $"Access granted to '{resource}' for '{username}' ({normalizedRole}).",
            Resource: resource,
            RequiredRoles: requiredRolesDisplay,
            Username: username,
            ActualRole: normalizedRole
        );
    }

    public AccessControlResult AuthorizeAdminDashboard(string? token) =>
        AuthorizeByToken(token, "/api/admin/dashboard", VaultRoles.Admin);

    public AccessControlResult AuthorizeRoleManagement(string? token) =>
        AuthorizeByToken(token, "/api/admin/users/role", VaultRoles.Admin);

    public AccessControlResult AuthorizeAuditLogs(string? token) =>
        AuthorizeByToken(token, "/api/audit/logs", VaultRoles.Admin, VaultRoles.Auditor);

    public AccessControlResult AuthorizeUserVault(string? token) =>
        AuthorizeByToken(token, "/api/vault/profile", VaultRoles.Admin, VaultRoles.Auditor, VaultRoles.User);

    private string ComputeSignature(string payloadBase64)
    {
        using var hmac = new HMACSHA256(_signingKey);
        var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(payloadBase64));
        return Base64UrlEncode(signatureBytes);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
        }
        return Convert.FromBase64String(padded);
    }
}
