using SafeVault.Models;

namespace SafeVault.Services;

public class PasswordHasher
{
    public const int DefaultWorkFactor = 12;
    private const int MinWorkFactor = 4;
    private const int MaxWorkFactor = 16;

    // Precomputed dummy hash used for constant-time fallback when a username does not exist
    private static readonly string DummyHash =
        BCrypt.Net.BCrypt.HashPassword("SafeVault_ConstantTime_Fallback_Seed!2026", DefaultWorkFactor);

    private readonly int _workFactor;

    public PasswordHasher(int workFactor = DefaultWorkFactor)
    {
        if (workFactor < MinWorkFactor || workFactor > MaxWorkFactor)
        {
            throw new ArgumentOutOfRangeException(
                nameof(workFactor),
                $"BCrypt work factor must be between {MinWorkFactor} and {MaxWorkFactor}."
            );
        }

        _workFactor = workFactor;
    }

    public string HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password cannot be empty or whitespace.", nameof(password));
        }

        return BCrypt.Net.BCrypt.HashPassword(password, _workFactor);
    }

    public bool VerifyPassword(string? password, string? storedHash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        if (!storedHash.StartsWith("$2a$") && !storedHash.StartsWith("$2b$") && !storedHash.StartsWith("$2y$"))
        {
            return false;
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(password, storedHash);
        }
        catch
        {
            return false;
        }
    }

    public void VerifyConstantTimeFallback(string? password)
    {
        try
        {
            _ = BCrypt.Net.BCrypt.Verify(password ?? string.Empty, DummyHash);
        }
        catch
        {
            // Ignore fallback exceptions
        }
    }

    public HashInspectionResult InspectHashMetadata(string? hash)
    {
        if (string.IsNullOrWhiteSpace(hash) || hash.Length != 60 || !hash.StartsWith("$2"))
        {
            return new HashInspectionResult("Unknown", 0, string.Empty, hash?.Length ?? 0, false);
        }

        var parts = hash.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !int.TryParse(parts[1], out var cost))
        {
            return new HashInspectionResult("Unknown", 0, string.Empty, hash.Length, false);
        }

        var algo = $"${parts[0]}$ (BCrypt)";
        var saltAndCipher = parts[2];
        var saltPrefix = saltAndCipher.Length >= 22 ? saltAndCipher[..22] : saltAndCipher;

        return new HashInspectionResult(algo, cost, saltPrefix, hash.Length, true);
    }
}
