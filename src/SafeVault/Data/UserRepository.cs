using System.Data;
using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

public class UserRepository : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly bool _ownsConnection;

    public UserRepository(string connectionString = "Data Source=safevault.db")
    {
        _connection = new SqliteConnection(connectionString);
        _connection.Open();
        _ownsConnection = true;
    }

    public UserRepository(SqliteConnection connection)
    {
        _connection = connection;
        if (_connection.State != ConnectionState.Open)
        {
            _connection.Open();
        }
        _ownsConnection = false;
    }

    public void InitializeSchema()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL DEFAULT '',
                Role TEXT NOT NULL DEFAULT 'User',
                CreatedAt TEXT NOT NULL DEFAULT (datetime('now'))
            );";
        command.ExecuteNonQuery();

        EnsureColumnExists("PasswordHash", "TEXT NOT NULL DEFAULT ''");
        EnsureColumnExists("Role", "TEXT NOT NULL DEFAULT 'User'");
        EnsureColumnExists("CreatedAt", "TEXT NOT NULL DEFAULT ''");
    }

    private void EnsureColumnExists(string columnName, string columnDefinition)
    {
        using var pragmaCmd = _connection.CreateCommand();
        pragmaCmd.CommandText = "PRAGMA table_info(Users);";
        using var reader = pragmaCmd.ExecuteReader();
        while (reader.Read())
        {
            var existingName = reader.GetString(1);
            if (string.Equals(existingName, columnName, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }
        reader.Close();

        using var alterCmd = _connection.CreateCommand();
        alterCmd.CommandText = $"ALTER TABLE Users ADD COLUMN {columnName} {columnDefinition};";
        alterCmd.ExecuteNonQuery();
    }

    public async Task<int> CreateUserAsync(string username, string email)
    {
        return await CreateAuthenticatedUserAsync(username, email, string.Empty, VaultRoles.User);
    }

    public async Task<int> CreateAuthenticatedUserAsync(
        string username,
        string email,
        string passwordHash,
        string role = VaultRoles.User)
    {
        var normalizedRole = VaultRoles.IsValidRole(role)
            ? VaultRoles.NormalizeRole(role)
            : VaultRoles.User;
        var createdAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");

        using var command = _connection.CreateCommand();
        // Parameterized query: inputs are bound as parameters, preventing SQL injection
        command.CommandText = @"
            INSERT INTO Users (Username, Email, PasswordHash, Role, CreatedAt) 
            VALUES (@Username, @Email, @PasswordHash, @Role, @CreatedAt);
            SELECT last_insert_rowid();";

        command.Parameters.AddWithValue("@Username", username);
        command.Parameters.AddWithValue("@Email", email);
        command.Parameters.AddWithValue("@PasswordHash", passwordHash);
        command.Parameters.AddWithValue("@Role", normalizedRole);
        command.Parameters.AddWithValue("@CreatedAt", createdAt);

        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    public async Task<UserRecord?> GetUserByUsernameAsync(string username)
    {
        var account = await GetUserAccountByUsernameAsync(username);
        if (account is null)
        {
            return null;
        }

        return new UserRecord(account.UserId, account.Username, account.Email);
    }

    public async Task<UserAccountRecord?> GetUserAccountByUsernameAsync(string username)
    {
        using var command = _connection.CreateCommand();
        // Parameterized query: input is strictly treated as a literal value
        command.CommandText = @"
            SELECT UserID, Username, Email, PasswordHash, Role, CreatedAt 
            FROM Users 
            WHERE Username = @Username 
            LIMIT 1;";

        command.Parameters.AddWithValue("@Username", username);

        using var reader = await command.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return new UserAccountRecord(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                reader.IsDBNull(4) ? VaultRoles.User : reader.GetString(4),
                reader.IsDBNull(5) ? string.Empty : reader.GetString(5)
            );
        }

        return null;
    }

    public async Task<bool> UpdateUserRoleAsync(string username, string newRole)
    {
        if (!VaultRoles.IsValidRole(newRole))
        {
            return false;
        }

        var normalizedRole = VaultRoles.NormalizeRole(newRole);
        using var command = _connection.CreateCommand();
        command.CommandText = @"
            UPDATE Users 
            SET Role = @Role 
            WHERE Username = @Username;";

        command.Parameters.AddWithValue("@Role", normalizedRole);
        command.Parameters.AddWithValue("@Username", username);

        var rows = await command.ExecuteNonQueryAsync();
        return rows > 0;
    }

    public async Task<IReadOnlyList<UserRecord>> GetAllUsersAsync()
    {
        var accounts = await GetAllUserAccountsAsync();
        return accounts
            .Select(a => new UserRecord(a.UserId, a.Username, a.Email))
            .ToList();
    }

    public async Task<IReadOnlyList<UserAccountRecord>> GetAllUserAccountsAsync()
    {
        var users = new List<UserAccountRecord>();
        using var command = _connection.CreateCommand();
        command.CommandText = @"
            SELECT UserID, Username, Email, PasswordHash, Role, CreatedAt 
            FROM Users 
            ORDER BY UserID ASC;";

        using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            users.Add(new UserAccountRecord(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                reader.IsDBNull(4) ? VaultRoles.User : reader.GetString(4),
                reader.IsDBNull(5) ? string.Empty : reader.GetString(5)
            ));
        }

        return users;
    }

    public bool TableExists(string tableName)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = @"
            SELECT COUNT(*) 
            FROM sqlite_master 
            WHERE type = 'table' AND name = @TableName;";
        command.Parameters.AddWithValue("@TableName", tableName);

        var count = Convert.ToInt32(command.ExecuteScalar());
        return count > 0;
    }

    public void Dispose()
    {
        if (_ownsConnection)
        {
            _connection.Dispose();
        }
    }
}
