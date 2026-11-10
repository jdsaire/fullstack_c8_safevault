using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

public class UserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString = "Data Source=safevault.db")
    {
        _connectionString = connectionString;
    }

    public void InitializeSchema()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL
            );";
        command.ExecuteNonQuery();
    }

    public async Task<int> CreateUserAsync(string username, string email)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        using var command = connection.CreateCommand();
        // Parameterized query using placeholders prevents SQL injection
        command.CommandText = @"
            INSERT INTO Users (Username, Email) 
            VALUES (@Username, @Email);
            SELECT last_insert_rowid();";

        command.Parameters.AddWithValue("@Username", username);
        command.Parameters.AddWithValue("@Email", email);

        var result = await command.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    public async Task<UserRecord?> GetUserByUsernameAsync(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        using var command = connection.CreateCommand();
        // Parameterized query: user input is bound to parameter and never concatenated
        command.CommandText = @"
            SELECT UserID, Username, Email 
            FROM Users 
            WHERE Username = @Username 
            LIMIT 1;";

        command.Parameters.AddWithValue("@Username", username);

        using var reader = await command.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return new UserRecord(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2)
            );
        }

        return null;
    }

    public async Task<IReadOnlyList<UserRecord>> GetAllUsersAsync()
    {
        var users = new List<UserRecord>();
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users ORDER BY UserID ASC;";

        using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            users.Add(new UserRecord(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2)
            ));
        }

        return users;
    }

    public bool TableExists(string tableName)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = @"
            SELECT COUNT(*) 
            FROM sqlite_master 
            WHERE type = 'table' AND name = @TableName;";
        command.Parameters.AddWithValue("@TableName", tableName);

        var count = Convert.ToInt32(command.ExecuteScalar());
        return count > 0;
    }
}
