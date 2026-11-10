using System.Net;
using System.Text.RegularExpressions;
using SafeVault.Models;

namespace SafeVault.Services;

public class InputValidator
{
    private static readonly Regex UsernamePattern = new(
        @"^[a-zA-Z0-9_\-\.]{3,50}$",
        RegexOptions.Compiled
    );

    private static readonly Regex EmailPattern = new(
        @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    private static readonly Regex ScriptTagPattern = new(
        @"<[^>]*>|javascript:|onerror=|onload=|onclick=",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    public string Sanitize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        // Remove dangerous script patterns and event handlers
        var stripped = ScriptTagPattern.Replace(input, string.Empty).Trim();

        // HTML encode to prevent stored/reflected XSS
        return WebUtility.HtmlEncode(stripped);
    }

    public ValidationResult ValidateAndSanitize(string? username, string? email)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(username))
        {
            errors.Add("Username is required.");
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
        else if (email.Length > 100)
        {
            errors.Add("Email must not exceed 100 characters.");
        }
        else if (!EmailPattern.IsMatch(email))
        {
            errors.Add("Email format is invalid.");
        }

        var sanitizedUsername = Sanitize(username);
        var sanitizedEmail = Sanitize(email);

        var isValid = errors.Count == 0;
        return new ValidationResult(isValid, sanitizedUsername, sanitizedEmail, errors);
    }
}
