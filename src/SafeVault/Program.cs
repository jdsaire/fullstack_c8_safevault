using Microsoft.Extensions.FileProviders;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

// Register application services
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? "Data Source=safevault.db";

var userRepository = new UserRepository(connectionString);
userRepository.InitializeSchema();

var inputValidator = new InputValidator();
var passwordHasher = new PasswordHasher();
var authorizationService = new AuthorizationService();
var authService = new AuthService(
    userRepository,
    inputValidator,
    passwordHasher,
    account => authorizationService.IssueSessionToken(account)
);
var securityAuditService = new SecurityAuditService(
    userRepository,
    inputValidator,
    authorizationService
);

// Seed baseline demonstration accounts if not present
await SeedDefaultAccountsAsync(authService, userRepository);

builder.Services.AddSingleton(userRepository);
builder.Services.AddSingleton(inputValidator);
builder.Services.AddSingleton(passwordHasher);
builder.Services.AddSingleton(authorizationService);
builder.Services.AddSingleton(authService);
builder.Services.AddSingleton(securityAuditService);

var app = builder.Build();

// Activity 3: Defensive HTTP Security Headers Middleware
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-XSS-Protection"] = "0";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'";
    await next();
});

var repoRootPath = Path.GetFullPath(Path.Combine(app.Environment.ContentRootPath, "../.."));
if (Directory.Exists(repoRootPath))
{
    var fileProvider = new PhysicalFileProvider(repoRootPath);
    app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = fileProvider });
    app.UseStaticFiles(new StaticFileOptions { FileProvider = fileProvider });
}
else
{
    app.UseDefaultFiles();
    app.UseStaticFiles();
}

// Serve index.html or webform.html at root
app.MapGet("/", async context =>
{
    var htmlPath = Path.Combine(repoRootPath, "index.html");
    if (!File.Exists(htmlPath))
    {
        htmlPath = Path.Combine(repoRootPath, "webform.html");
    }
    if (!File.Exists(htmlPath))
    {
        htmlPath = Path.Combine(AppContext.BaseDirectory, "index.html");
    }
    if (File.Exists(htmlPath))
    {
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.SendFileAsync(htmlPath);
    }
    else
    {
        context.Response.StatusCode = 200;
        await context.Response.WriteAsync("SafeVault API is running.");
    }
});

// Activity 1 & 3: Secure submission endpoint with input validation, duplicate guard, and parameterized storage
app.MapPost("/submit", async (UserSubmission submission, InputValidator validator, UserRepository repository) =>
{
    var validationResult = validator.ValidateAndSanitize(submission.Username, submission.Email);
    if (!validationResult.IsValid)
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Input validation failed.",
            errors = validationResult.Errors
        });
    }

    try
    {
        var existing = await repository.GetUserAccountByUsernameAsync(validationResult.SanitizedUsername!);
        if (existing is not null)
        {
            return Results.Conflict(new
            {
                success = false,
                message = "Username is already registered."
            });
        }

        var userId = await repository.CreateUserAsync(
            validationResult.SanitizedUsername!,
            validationResult.SanitizedEmail!
        );

        return Results.Ok(new
        {
            success = true,
            message = "User registered successfully with validated input and parameterized query.",
            userId = userId,
            username = validationResult.SanitizedUsername,
            email = validationResult.SanitizedEmail
        });
    }
    catch (Exception)
    {
        return Results.Problem(
            detail: "An error occurred while processing the request securely.",
            statusCode: 500
        );
    }
});

// Activity 3: Parameterized wildcard-safe user search endpoint
app.MapGet("/api/users/search", async (string? q, InputValidator validator, UserRepository repository) =>
{
    var check = validator.ValidateSearchQuery(q);
    if (!check.IsValid)
    {
        return Results.BadRequest(new SearchUsersResult(
            IsValid: false,
            Query: q ?? string.Empty,
            EscapedPattern: string.Empty,
            MatchCount: 0,
            Matches: Array.Empty<UserRecord>(),
            Errors: check.Errors
        ));
    }

    var matches = await repository.SearchUsersAsync(q);
    return Results.Ok(new SearchUsersResult(
        IsValid: true,
        Query: check.SanitizedQuery,
        EscapedPattern: $"%{check.EscapedLikePattern}%",
        MatchCount: matches.Count,
        Matches: matches,
        Errors: Array.Empty<string>()
    ));
});

// Activity 1 & 3: Secure lookup endpoint with input validation and parameterized query
app.MapGet("/api/users/{username}", async (string username, InputValidator validator, UserRepository repository) =>
{
    if (!validator.IsValidUsername(username))
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Invalid username format."
        });
    }

    var user = await repository.GetUserByUsernameAsync(username);
    return user is not null ? Results.Ok(user) : Results.NotFound();
});

// Activity 2: User registration with salted BCrypt password hashing and role assignment
app.MapPost("/api/auth/register", async (RegisterUserRequest request, AuthService auth, PasswordHasher hasher, UserRepository repository) =>
{
    var result = await auth.RegisterUserAsync(request.Username, request.Email, request.Password, request.Role);
    if (!result.IsAuthenticated)
    {
        return Results.Json(result, statusCode: result.StatusCode);
    }

    var account = await repository.GetUserAccountByUsernameAsync(result.Username!);
    var metadata = hasher.InspectHashMetadata(account?.PasswordHash);

    return Results.Json(new
    {
        result.IsAuthenticated,
        result.StatusCode,
        result.Message,
        result.UserId,
        result.Username,
        result.Email,
        result.Role,
        result.Token,
        hashMetadata = metadata
    }, statusCode: result.StatusCode);
});

// Activity 2: User authentication endpoint verifying username and BCrypt password hash
app.MapPost("/api/auth/login", async (LoginRequest request, AuthService auth) =>
{
    var result = await auth.AuthenticateAsync(request.Username, request.Password);
    return Results.Json(result, statusCode: result.StatusCode);
});

// Activity 2: Protected Admin Dashboard endpoint (RBAC: Admin role only)
app.MapGet("/api/admin/dashboard", async (HttpContext context, AuthorizationService authz, UserRepository repository) =>
{
    var token = ExtractAuthorizationHeader(context);
    var decision = authz.AuthorizeAdminDashboard(token);
    if (!decision.IsAuthorized)
    {
        return Results.Json(decision, statusCode: decision.StatusCode);
    }

    var accounts = await repository.GetAllUserAccountsAsync();
    return Results.Ok(new
    {
        access = decision,
        totalUsers = accounts.Count,
        users = accounts.Select(u => new
        {
            u.UserId,
            u.Username,
            u.Email,
            u.Role,
            u.CreatedAt,
            hasPasswordHash = !string.IsNullOrWhiteSpace(u.PasswordHash)
        })
    });
});

// Activity 2: Protected Role Management endpoint (RBAC: Admin role only)
app.MapPost("/api/admin/users/{username}/role", async (
    string username,
    RoleUpdateRequest request,
    HttpContext context,
    AuthorizationService authz,
    UserRepository repository) =>
{
    var token = ExtractAuthorizationHeader(context);
    var decision = authz.AuthorizeRoleManagement(token);
    if (!decision.IsAuthorized)
    {
        return Results.Json(decision, statusCode: decision.StatusCode);
    }

    if (string.IsNullOrWhiteSpace(request.NewRole) || !VaultRoles.IsValidRole(request.NewRole))
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Invalid role specified. Allowed roles: Admin, Auditor, User."
        });
    }

    var updated = await repository.UpdateUserRoleAsync(username, request.NewRole);
    if (!updated)
    {
        return Results.NotFound(new
        {
            success = false,
            message = $"User '{username}' not found."
        });
    }

    return Results.Ok(new
    {
        success = true,
        message = $"Role for '{username}' updated to '{VaultRoles.NormalizeRole(request.NewRole)}'.",
        authorizedBy = decision.Username
    });
});

// Activity 2: Protected Security Audit Logs endpoint (RBAC: Admin and Auditor roles)
app.MapGet("/api/audit/logs", (HttpContext context, AuthorizationService authz) =>
{
    var token = ExtractAuthorizationHeader(context);
    var decision = authz.AuthorizeAuditLogs(token);
    if (!decision.IsAuthorized)
    {
        return Results.Json(decision, statusCode: decision.StatusCode);
    }

    return Results.Ok(new
    {
        access = decision,
        entries = new[]
        {
            new { eventId = "AUD-101", category = "Authentication", detail = "BCrypt cost=12 verification active", status = "Verified" },
            new { eventId = "AUD-102", category = "Authorization", detail = "RBAC route gate enforced on /api/admin/dashboard", status = "Enforced" },
            new { eventId = "AUD-103", category = "DataLayer", detail = "SqliteParameter literal bindings active on Users table", status = "Protected" },
            new { eventId = "AUD-104", category = "Remediation", detail = "Activity 3 email regex, XSS, wildcard search, and token delimiter guards active", status = "Remediated" }
        }
    });
});

// Activity 2: Protected User Vault Profile endpoint (RBAC: Admin, Auditor, and User roles)
app.MapGet("/api/vault/profile", async (HttpContext context, AuthorizationService authz, UserRepository repository) =>
{
    var token = ExtractAuthorizationHeader(context);
    var decision = authz.AuthorizeUserVault(token);
    if (!decision.IsAuthorized)
    {
        return Results.Json(decision, statusCode: decision.StatusCode);
    }

    var account = await repository.GetUserAccountByUsernameAsync(decision.Username!);
    return Results.Ok(new
    {
        access = decision,
        profile = account is null
            ? null
            : new
            {
                account.UserId,
                account.Username,
                account.Email,
                account.Role,
                account.CreatedAt
            }
    });
});

// Activity 3: Security Vulnerability Audit & Remediation Probe Endpoints
app.MapGet("/api/security/audit", (SecurityAuditService auditService) =>
{
    var findings = auditService.GetVulnerabilityFindings();
    return Results.Ok(new
    {
        measuredCount = findings.Count(f => f.ProvenanceBadge.Contains("[M]")),
        simulatedCount = findings.Count(f => f.ProvenanceBadge.Contains("[SIM]")),
        totalFindings = findings.Count,
        findings
    });
});

app.MapPost("/api/security/probe", async (RemediationProbeRequest request, SecurityAuditService auditService) =>
{
    var result = await auditService.ExecuteRemediationProbeAsync(request.VectorCategory, request.Payload);
    return Results.Ok(result);
});

app.Run();

static string? ExtractAuthorizationHeader(HttpContext context)
{
    if (context.Request.Headers.TryGetValue("Authorization", out var authHeader) &&
        !string.IsNullOrWhiteSpace(authHeader))
    {
        return authHeader.ToString();
    }

    if (context.Request.Headers.TryGetValue("X-Vault-Token", out var customHeader) &&
        !string.IsNullOrWhiteSpace(customHeader))
    {
        return customHeader.ToString();
    }

    return null;
}

static async Task SeedDefaultAccountsAsync(AuthService authService, UserRepository repository)
{
    if (await repository.GetUserAccountByUsernameAsync("admin_vault") is null)
    {
        await authService.RegisterUserAsync("admin_vault", "admin@safevault.local", "AdminVault#2026", VaultRoles.Admin);
    }

    if (await repository.GetUserAccountByUsernameAsync("carol_audit") is null)
    {
        await authService.RegisterUserAsync("carol_audit", "carol@audit.internal", "AuditVault#2026", VaultRoles.Auditor);
    }

    if (await repository.GetUserAccountByUsernameAsync("alice_vault") is null)
    {
        await authService.RegisterUserAsync("alice_vault", "alice@safevault.local", "AliceVault#2026", VaultRoles.User);
    }
}

// Partial class for integration test reference if needed
public partial class Program { }
