using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services;

public class AuthService
{
    private readonly UserRepository _repository;
    private readonly InputValidator _validator;
    private readonly PasswordHasher _passwordHasher;
    private readonly Func<UserAccountRecord, string>? _tokenIssuer;

    public AuthService(
        UserRepository repository,
        InputValidator validator,
        PasswordHasher passwordHasher,
        Func<UserAccountRecord, string>? tokenIssuer = null)
    {
        _repository = repository;
        _validator = validator;
        _passwordHasher = passwordHasher;
        _tokenIssuer = tokenIssuer;
    }

    public IReadOnlyList<string> ValidatePasswordStrength(string? password)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(password))
        {
            errors.Add("Password is required.");
            return errors;
        }

        if (password.Length < 8 || password.Length > 128)
        {
            errors.Add("Password must be between 8 and 128 characters.");
        }

        if (!password.Any(char.IsLetter) || !password.Any(char.IsDigit))
        {
            errors.Add("Password must include at least one letter and one digit.");
        }

        return errors;
    }

    public async Task<AuthResult> RegisterUserAsync(
        string? username,
        string? email,
        string? password,
        string? role = VaultRoles.User)
    {
        var validation = _validator.ValidateAndSanitize(username, email);
        var errors = new List<string>(validation.Errors);

        errors.AddRange(ValidatePasswordStrength(password));

        var effectiveRole = string.IsNullOrWhiteSpace(role) ? VaultRoles.User : role.Trim();
        if (!VaultRoles.IsValidRole(effectiveRole))
        {
            errors.Add("Specified role is invalid. Allowed roles: Admin, Auditor, User.");
        }

        if (errors.Count > 0)
        {
            return new AuthResult(
                IsAuthenticated: false,
                StatusCode: 400,
                Message: "Registration validation failed.",
                UserId: null,
                Username: validation.SanitizedUsername,
                Email: validation.SanitizedEmail,
                Role: null,
                Token: null,
                Errors: errors
            );
        }

        var normalizedRole = VaultRoles.NormalizeRole(effectiveRole);
        var existing = await _repository.GetUserAccountByUsernameAsync(validation.SanitizedUsername!);
        if (existing is not null)
        {
            return new AuthResult(
                IsAuthenticated: false,
                StatusCode: 409,
                Message: "Username is already registered.",
                UserId: null,
                Username: validation.SanitizedUsername,
                Email: validation.SanitizedEmail,
                Role: null,
                Token: null,
                Errors: new[] { "Username is already registered." }
            );
        }

        var passwordHash = _passwordHasher.HashPassword(password!);
        var userId = await _repository.CreateAuthenticatedUserAsync(
            validation.SanitizedUsername!,
            validation.SanitizedEmail!,
            passwordHash,
            normalizedRole
        );

        var account = new UserAccountRecord(
            userId,
            validation.SanitizedUsername!,
            validation.SanitizedEmail!,
            passwordHash,
            normalizedRole,
            DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")
        );

        var token = _tokenIssuer?.Invoke(account);

        return new AuthResult(
            IsAuthenticated: true,
            StatusCode: 201,
            Message: "User registered securely with salted BCrypt password hash.",
            UserId: userId,
            Username: account.Username,
            Email: account.Email,
            Role: account.Role,
            Token: token,
            Errors: Array.Empty<string>()
        );
    }

    public async Task<AuthResult> AuthenticateAsync(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            _passwordHasher.VerifyConstantTimeFallback(password);
            return new AuthResult(
                IsAuthenticated: false,
                StatusCode: 401,
                Message: "Invalid username or password.",
                UserId: null,
                Username: null,
                Email: null,
                Role: null,
                Token: null,
                Errors: new[] { "Username and password are required." }
            );
        }

        var trimmedUsername = username.Trim();

        // Lookup via parameterized query in UserRepository (resistant to SQL injection)
        var account = await _repository.GetUserAccountByUsernameAsync(trimmedUsername);
        if (account is null || string.IsNullOrWhiteSpace(account.PasswordHash))
        {
            _passwordHasher.VerifyConstantTimeFallback(password);
            return new AuthResult(
                IsAuthenticated: false,
                StatusCode: 401,
                Message: "Invalid username or password.",
                UserId: null,
                Username: null,
                Email: null,
                Role: null,
                Token: null,
                Errors: new[] { "Invalid credentials." }
            );
        }

        var verified = _passwordHasher.VerifyPassword(password, account.PasswordHash);
        if (!verified)
        {
            return new AuthResult(
                IsAuthenticated: false,
                StatusCode: 401,
                Message: "Invalid username or password.",
                UserId: null,
                Username: null,
                Email: null,
                Role: null,
                Token: null,
                Errors: new[] { "Invalid credentials." }
            );
        }

        var token = _tokenIssuer?.Invoke(account);

        return new AuthResult(
            IsAuthenticated: true,
            StatusCode: 200,
            Message: "Authentication successful.",
            UserId: account.UserId,
            Username: account.Username,
            Email: account.Email,
            Role: account.Role,
            Token: token,
            Errors: Array.Empty<string>()
        );
    }
}
