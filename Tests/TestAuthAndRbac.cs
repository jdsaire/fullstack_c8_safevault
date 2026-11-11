// Tests/TestAuthAndRbac.cs
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public class TestAuthAndRbac
{
    private UserRepository _repository = null!;
    private InputValidator _validator = null!;
    private PasswordHasher _passwordHasher = null!;
    private AuthorizationService _authorizationService = null!;
    private AuthService _authService = null!;

    [SetUp]
    public void Setup()
    {
        _repository = new UserRepository("Data Source=:memory:");
        _repository.InitializeSchema();
        _validator = new InputValidator();
        _passwordHasher = new PasswordHasher(workFactor: 10);
        _authorizationService = new AuthorizationService();
        _authService = new AuthService(
            _repository,
            _validator,
            _passwordHasher,
            account => _authorizationService.IssueSessionToken(account)
        );
    }

    [TearDown]
    public void TearDown()
    {
        _repository.Dispose();
    }

    [Test]
    public void TestPasswordHashing_GeneratesUniqueSaltsAndVerifiesCorrectly()
    {
        var defaultHasher = new PasswordHasher(); // DefaultWorkFactor = 12
        const string rawPassword = "VaultSecret#2026!";

        var hashOne = defaultHasher.HashPassword(rawPassword);
        var hashTwo = defaultHasher.HashPassword(rawPassword);

        // Two hashes of the identical password must differ due to unique 128-bit salts
        Assert.That(hashOne, Is.Not.EqualTo(hashTwo));
        Assert.That(hashOne.Length, Is.EqualTo(60));

        var metaOne = defaultHasher.InspectHashMetadata(hashOne);
        var metaTwo = defaultHasher.InspectHashMetadata(hashTwo);

        Assert.That(metaOne.IsValidFormat, Is.True);
        Assert.That(metaOne.WorkFactor, Is.EqualTo(PasswordHasher.DefaultWorkFactor));
        Assert.That(metaOne.SaltPrefix, Is.Not.EqualTo(metaTwo.SaltPrefix));

        // Verification succeeds for original password and fails for altered password
        Assert.That(defaultHasher.VerifyPassword(rawPassword, hashOne), Is.True);
        Assert.That(defaultHasher.VerifyPassword(rawPassword, hashTwo), Is.True);
        Assert.That(defaultHasher.VerifyPassword("WrongPassword#2026!", hashOne), Is.False);
    }

    [Test]
    public async Task TestLogin_ValidCredentials_AuthenticatesAndIssuesSignedToken()
    {
        var regResult = await _authService.RegisterUserAsync(
            "alice_auth",
            "alice@safevault.local",
            "AlicePass#2026",
            VaultRoles.User
        );

        Assert.That(regResult.IsAuthenticated, Is.True);
        Assert.That(regResult.StatusCode, Is.EqualTo(201));

        // Verify stored record holds a BCrypt hash, never plaintext
        var stored = await _repository.GetUserAccountByUsernameAsync("alice_auth");
        Assert.That(stored, Is.Not.Null);
        Assert.That(stored!.PasswordHash, Does.StartWith("$2"));
        Assert.That(stored.PasswordHash, Is.Not.EqualTo("AlicePass#2026"));

        var loginResult = await _authService.AuthenticateAsync("alice_auth", "AlicePass#2026");

        Assert.That(loginResult.IsAuthenticated, Is.True);
        Assert.That(loginResult.StatusCode, Is.EqualTo(200));
        Assert.That(loginResult.Username, Is.EqualTo("alice_auth"));
        Assert.That(loginResult.Role, Is.EqualTo(VaultRoles.User));
        Assert.That(loginResult.Token, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public async Task TestLogin_InvalidPassword_RejectsWithUnauthorized()
    {
        await _authService.RegisterUserAsync(
            "bob_sec",
            "bob@safevault.local",
            "CorrectHorseBattery#9",
            VaultRoles.User
        );

        var loginResult = await _authService.AuthenticateAsync("bob_sec", "WrongPassword#1");

        Assert.That(loginResult.IsAuthenticated, Is.False);
        Assert.That(loginResult.StatusCode, Is.EqualTo(401));
        Assert.That(loginResult.Token, Is.Null);
        Assert.That(loginResult.Message, Is.EqualTo("Invalid username or password."));
    }

    [Test]
    public async Task TestLogin_NonExistentUser_RejectsSafelyWithoutEnumeration()
    {
        var loginResult = await _authService.AuthenticateAsync("non_existent_user", "AnyPassword#123");

        Assert.That(loginResult.IsAuthenticated, Is.False);
        Assert.That(loginResult.StatusCode, Is.EqualTo(401));
        Assert.That(loginResult.Token, Is.Null);
        Assert.That(loginResult.Message, Is.EqualTo("Invalid username or password."));
    }

    [Test]
    public async Task TestLogin_SqlInjectionPayloads_AreNeutralized()
    {
        await _authService.RegisterUserAsync(
            "admin_vault",
            "admin@safevault.local",
            "AdminStrong#2026",
            VaultRoles.Admin
        );

        string[] sqliPayloads =
        {
            "admin_vault' --",
            "' OR '1'='1",
            "admin' OR 1=1 --",
            "'; DROP TABLE Users; --"
        };

        foreach (var payload in sqliPayloads)
        {
            var attemptByUsername = await _authService.AuthenticateAsync(payload, "any_password");
            Assert.That(attemptByUsername.IsAuthenticated, Is.False, $"SQLi login bypass must fail for username: {payload}");
            Assert.That(attemptByUsername.StatusCode, Is.EqualTo(401));

            var attemptByPassword = await _authService.AuthenticateAsync("admin_vault", payload);
            Assert.That(attemptByPassword.IsAuthenticated, Is.False, $"SQLi login bypass must fail for password: {payload}");
            Assert.That(attemptByPassword.StatusCode, Is.EqualTo(401));
        }

        Assert.That(_repository.TableExists("Users"), Is.True, "Users table must remain intact after SQLi login attempts");
    }

    [Test]
    public async Task TestRbac_AdminRole_GrantedAccessToAdminDashboardAndRoleManagement()
    {
        await _authService.RegisterUserAsync("root_admin", "root@safevault.local", "AdminSecret#88", VaultRoles.Admin);
        await _authService.RegisterUserAsync("junior_user", "junior@safevault.local", "UserSecret#88", VaultRoles.User);

        var adminLogin = await _authService.AuthenticateAsync("root_admin", "AdminSecret#88");
        Assert.That(adminLogin.IsAuthenticated, Is.True);

        var dashboardAccess = _authorizationService.AuthorizeAdminDashboard(adminLogin.Token);
        Assert.That(dashboardAccess.IsAuthorized, Is.True);
        Assert.That(dashboardAccess.StatusCode, Is.EqualTo(200));
        Assert.That(dashboardAccess.ActualRole, Is.EqualTo(VaultRoles.Admin));

        var roleMgmtAccess = _authorizationService.AuthorizeRoleManagement(adminLogin.Token);
        Assert.That(roleMgmtAccess.IsAuthorized, Is.True);

        var updated = await _repository.UpdateUserRoleAsync("junior_user", VaultRoles.Auditor);
        Assert.That(updated, Is.True);

        var updatedAccount = await _repository.GetUserAccountByUsernameAsync("junior_user");
        Assert.That(updatedAccount!.Role, Is.EqualTo(VaultRoles.Auditor));
    }

    [Test]
    public async Task TestRbac_StandardUserRole_DeniedAccessToAdminDashboard()
    {
        await _authService.RegisterUserAsync("standard_user", "user@safevault.local", "StandardPass#11", VaultRoles.User);
        var userLogin = await _authService.AuthenticateAsync("standard_user", "StandardPass#11");

        Assert.That(userLogin.IsAuthenticated, Is.True);
        Assert.That(userLogin.Role, Is.EqualTo(VaultRoles.User));

        // Standard user must be denied Admin Dashboard (403 Forbidden)
        var adminDecision = _authorizationService.AuthorizeAdminDashboard(userLogin.Token);
        Assert.That(adminDecision.IsAuthorized, Is.False);
        Assert.That(adminDecision.StatusCode, Is.EqualTo(403));

        // Standard user must be denied Security Audit Logs (403 Forbidden)
        var auditDecision = _authorizationService.AuthorizeAuditLogs(userLogin.Token);
        Assert.That(auditDecision.IsAuthorized, Is.False);
        Assert.That(auditDecision.StatusCode, Is.EqualTo(403));

        // Standard user is granted access to their own User Vault profile (200 OK)
        var profileDecision = _authorizationService.AuthorizeUserVault(userLogin.Token);
        Assert.That(profileDecision.IsAuthorized, Is.True);
        Assert.That(profileDecision.StatusCode, Is.EqualTo(200));
    }

    [Test]
    public async Task TestRbac_AuditorRole_GrantedAuditLogsButDeniedAdminDashboard()
    {
        await _authService.RegisterUserAsync("carol_audit", "carol@audit.local", "AuditPass#2026", VaultRoles.Auditor);
        var auditorLogin = await _authService.AuthenticateAsync("carol_audit", "AuditPass#2026");

        Assert.That(auditorLogin.IsAuthenticated, Is.True);
        Assert.That(auditorLogin.Role, Is.EqualTo(VaultRoles.Auditor));

        // Auditor is granted access to Audit Logs (200 OK)
        var auditDecision = _authorizationService.AuthorizeAuditLogs(auditorLogin.Token);
        Assert.That(auditDecision.IsAuthorized, Is.True);
        Assert.That(auditDecision.StatusCode, Is.EqualTo(200));

        // Auditor is denied access to Admin Dashboard (403 Forbidden)
        var adminDecision = _authorizationService.AuthorizeAdminDashboard(auditorLogin.Token);
        Assert.That(adminDecision.IsAuthorized, Is.False);
        Assert.That(adminDecision.StatusCode, Is.EqualTo(403));
    }

    [Test]
    public async Task TestRbac_UnauthenticatedOrTamperedToken_DeniedWith401()
    {
        // 1. Missing token
        var missingDecision = _authorizationService.AuthorizeAdminDashboard(null);
        Assert.That(missingDecision.IsAuthorized, Is.False);
        Assert.That(missingDecision.StatusCode, Is.EqualTo(401));

        // 2. Tampered token (attempting privilege escalation by modifying payload without HMAC key)
        await _authService.RegisterUserAsync("normal_acct", "norm@safevault.local", "NormPass#2026", VaultRoles.User);
        var login = await _authService.AuthenticateAsync("normal_acct", "NormPass#2026");

        var tokenParts = login.Token!.Split('.');
        var forgedPayload = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("1|normal_acct|Admin|9999999999")
        ).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var forgedToken = $"{forgedPayload}.{tokenParts[1]}";

        var forgedDecision = _authorizationService.AuthorizeAdminDashboard(forgedToken);
        Assert.That(forgedDecision.IsAuthorized, Is.False);
        Assert.That(forgedDecision.StatusCode, Is.EqualTo(401));
    }

    [Test]
    public async Task TestRbac_InvalidRoleOrWeakPassword_RejectedDuringRegistration()
    {
        var badRoleResult = await _authService.RegisterUserAsync(
            "rogue_user",
            "rogue@safevault.local",
            "StrongPass#2026",
            "SuperRoot"
        );

        Assert.That(badRoleResult.IsAuthenticated, Is.False);
        Assert.That(badRoleResult.StatusCode, Is.EqualTo(400));
        Assert.That(badRoleResult.Errors, Has.Some.Contains("Specified role is invalid"));

        var weakPassResult = await _authService.RegisterUserAsync(
            "weak_user",
            "weak@safevault.local",
            "short",
            VaultRoles.User
        );

        Assert.That(weakPassResult.IsAuthenticated, Is.False);
        Assert.That(weakPassResult.StatusCode, Is.EqualTo(400));
        Assert.That(weakPassResult.Errors, Has.Some.Contains("between 8 and 128 characters"));
    }
}
