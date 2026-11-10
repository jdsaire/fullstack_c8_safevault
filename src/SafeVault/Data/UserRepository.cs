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
                Email TEXT NOT NULL
            );";
        command.ExecuteNonQuery();
    }

    public async Task<int> CreateUserAsync(string username, string email)
    {
        using var command = _connection.CreateCommand();
        // Parameterized query: inputs are bound as parameters, preventing SQL injection
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
        using var command = _connection.CreateCommand();
        // Parameterized query: input is strictly treated as a literal value
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
        using var command = _connection.CreateCommand();
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
