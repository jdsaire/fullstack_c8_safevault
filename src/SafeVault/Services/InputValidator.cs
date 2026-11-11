using System.Net;
using System.Text.RegularExpressions;
using SafeVault.Models;

namespace SafeVault.Services;

public class InputValidator
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly Regex UsernamePattern = new(
        @"^[a-zA-Z0-9_\-\.]{3,50}$",
        RegexOptions.Compiled,
        RegexTimeout
    );

    private static readonly Regex EmailPattern = new(
        @"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexTimeout
    );

    private static readonly Regex ControlCharPattern = new(
        @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
        RegexOptions.Compiled,
        RegexTimeout
    );

    private static readonly Regex ScriptTagPattern = new(
        @"<[^>]*>|\bon[a-z0-9_]+\s*=|j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:|d\s*a\s*t\s*a\s*:\s*text\s*/\s*html",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        RegexTimeout
    );

    private static readonly char[] DisallowedEmailChars =
    {
        '<', '>', '"', '\'', ';', '(', ')', '|', '\\', '`'
    };

    public bool ContainsControlCharacters(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        foreach (var ch in input)
        {
            if (char.IsControl(ch))
            {
                return true;
            }
        }

        return false;
    }

    public string Sanitize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        // 1. Strip ASCII control characters and null bytes
        var cleaned = ControlCharPattern.Replace(input, string.Empty);

        // 2. Remove dangerous script tags, inline event handlers (on*=), and executable URI schemes
        var stripped = ScriptTagPattern.Replace(cleaned, string.Empty).Trim();

        // 3. HTML encode to prevent stored/reflected XSS
        return WebUtility.HtmlEncode(stripped);
    }

    public bool IsValidUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username) || ContainsControlCharacters(username))
        {
            return false;
        }

        return username.Length >= 3 && username.Length <= 50 && UsernamePattern.IsMatch(username);
    }

    public bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || ContainsControlCharacters(email))
        {
            return false;
        }

        if (email.Length > 100 || email.IndexOfAny(DisallowedEmailChars) >= 0)
        {
            return false;
        }

        return EmailPattern.IsMatch(email);
    }

    public ValidationResult ValidateAndSanitize(string? username, string? email)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(username))
        {
            errors.Add("Username is required.");
        }
        else if (ContainsControlCharacters(username))
        {
            errors.Add("Username contains invalid characters. Control characters are not permitted.");
        }
        else if (username.Length < 3 || username.Length > 50)
        {
            errors.Add("Username must be between 3 and 50 characters.");
        }
        else if (!UsernamePattern.IsMatch(username))
        {
            errors.Add("Username contains invalid characters. Only alphanumeric, underscores, hyphens, and periods are allowed.");
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            errors.Add("Email is required.");
        }
        else if (ContainsControlCharacters(email))
        {
            errors.Add("Email format is invalid. Control characters are not permitted.");
        }
        else if (email.Length > 100)
        {
            errors.Add("Email must not exceed 100 characters.");
        }
        else if (email.IndexOfAny(DisallowedEmailChars) >= 0 || !EmailPattern.IsMatch(email))
        {
            errors.Add("Email format is invalid.");
        }

        var sanitizedUsername = Sanitize(username);
        var sanitizedEmail = Sanitize(email);

        var isValid = errors.Count == 0;
        return new ValidationResult(isValid, sanitizedUsername, sanitizedEmail, errors);
    }

    public (bool IsValid, string SanitizedQuery, string EscapedLikePattern, IReadOnlyList<string> Errors) ValidateSearchQuery(string? rawQuery)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(rawQuery))
        {
            errors.Add("Search query is required.");
            return (false, string.Empty, string.Empty, errors);
        }

        if (ContainsControlCharacters(rawQuery))
        {
            errors.Add("Search query contains disallowed control characters.");
            return (false, string.Empty, string.Empty, errors);
        }

        var trimmed = rawQuery.Trim();
        if (trimmed.Length > 50)
        {
            errors.Add("Search query must not exceed 50 characters.");
            return (false, string.Empty, string.Empty, errors);
        }

        var sanitized = Sanitize(trimmed);
        var escapedLike = EscapeSqlLikeWildcards(trimmed);

        return (true, sanitized, escapedLike, errors);
    }

    public static string EscapeSqlLikeWildcards(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        return input
            .Replace(@"\", @"\\")
            .Replace("%", @"\%")
            .Replace("_", @"\_");
    }
}
