// Tests/TestInputValidation.cs
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Services;

[TestFixture]
public class TestInputValidation
{
    private UserRepository _repository = null!;
    private InputValidator _validator = null!;

    [SetUp]
    public void Setup()
    {
        // Use an isolated in-memory SQLite database for test execution
        _repository = new UserRepository("Data Source=:memory:");
        _repository.InitializeSchema();
        _validator = new InputValidator();
    }

    [TearDown]
    public void TearDown()
    {
        _repository.Dispose();
    }

    [Test]
    public void TestForSQLInjection()
    {
        // Setup legitimate baseline user
        var legitimateId = _repository.CreateUserAsync("alice_vault", "alice@safevault.local").Result;
        Assert.That(legitimateId, Is.GreaterThan(0));

        // Malicious SQL injection payloads designed to alter query logic or execute unauthorized commands
        string[] maliciousPayloads = new[]
        {
            "' OR '1'='1",
            "admin' --",
            "'; DROP TABLE Users; --",
            "' UNION SELECT 999, 'injected', 'injected@test.com' --",
            "' OR 1=1; --"
        };

        foreach (var payload in maliciousPayloads)
        {
            // 1. Verify insertion with parameterized command stores payload literally and safely
            int createdId = 0;
            Assert.DoesNotThrowAsync(async () =>
            {
                createdId = await _repository.CreateUserAsync(payload, "malicious@test.local");
            }, $"Failed inserting payload: {payload}");

            Assert.That(createdId, Is.GreaterThan(0));

            // 2. Verify query retrieval treats payload strictly as a literal parameter value
            var queriedUser = _repository.GetUserByUsernameAsync(payload).Result;
            Assert.That(queriedUser, Is.Not.Null, $"Failed querying literal user for: {payload}");
            Assert.That(queriedUser!.Username, Is.EqualTo(payload));

            // 3. Verify SQL injection cannot bypass logic to match other users
            var unintendedMatch = _repository.GetUserByUsernameAsync("' OR '1'='1").Result;
            if (payload == "' OR '1'='1'")
            {
                Assert.That(unintendedMatch!.Username, Is.EqualTo("' OR '1'='1'"));
            }
        }

        // 4. Verify table integrity: '; DROP TABLE Users; --' must not have dropped the table
        Assert.That(_repository.TableExists("Users"), Is.True, "Users table must remain intact");

        // 5. Verify the baseline legitimate user is still present and unchanged
        var alice = _repository.GetUserByUsernameAsync("alice_vault").Result;
        Assert.That(alice, Is.Not.Null);
        Assert.That(alice!.Email, Is.EqualTo("alice@safevault.local"));
    }

    [Test]
    public void TestForXSS()
    {
        // Malicious Cross-Site Scripting (XSS) vectors targeting input reflection and storage
        string[] xssPayloads = new[]
        {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('cookie')>",
            "<svg/onload=alert('document.domain')>",
            "javascript:alert(1)",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<a href=\"javascript:void(0)\" onclick=\"alert(1)\">Click</a>"
        };

        foreach (var payload in xssPayloads)
        {
            var sanitized = _validator.Sanitize(payload);

            // Verify raw executable tags and handlers are eliminated
            Assert.That(sanitized, Does.Not.Contain("<script>"));
            Assert.That(sanitized, Does.Not.Contain("</script>"));
            Assert.That(sanitized, Does.Not.Contain("<img"));
            Assert.That(sanitized, Does.Not.Contain("<svg"));
            Assert.That(sanitized, Does.Not.Contain("<iframe"));
            Assert.That(sanitized, Does.Not.Contain("onerror="));
            Assert.That(sanitized, Does.Not.Contain("onload="));
            Assert.That(sanitized, Does.Not.Contain("onclick="));
            Assert.That(sanitized, Does.Not.Contain("javascript:"));

            // Verify full validation pipeline rejects XSS payload when submitted as username
            var validation = _validator.ValidateAndSanitize(payload, "user@safevault.local");
            Assert.That(validation.IsValid, Is.False, $"XSS payload should fail strict username format: {payload}");
            Assert.That(validation.Errors, Has.Count.GreaterThan(0));
        }
    }

    [Test]
    public void TestValidInput_PassesValidation()
    {
        var result = _validator.ValidateAndSanitize("valid_user-99", "valid@safevault.local");

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Errors, Is.Empty);
        Assert.That(result.SanitizedUsername, Is.EqualTo("valid_user-99"));
        Assert.That(result.SanitizedEmail, Is.EqualTo("valid@safevault.local"));
    }

    [TestCase("", "user@test.com", "Username is required.")]
    [TestCase("ab", "user@test.com", "Username must be between 3 and 50 characters.")]
    [TestCase("invalid user name with spaces", "user@test.com", "Username contains invalid characters.")]
    [TestCase("valid_user", "", "Email is required.")]
    [TestCase("valid_user", "not-an-email", "Email format is invalid.")]
    public void TestInvalidInput_FailsValidation(string username, string email, string expectedErrorSubstring)
    {
        var result = _validator.ValidateAndSanitize(username, email);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Has.Some.Contains(expectedErrorSubstring));
    }
}
