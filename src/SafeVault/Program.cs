using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

// Register application services
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? "Data Source=safevault.db";

var userRepository = new UserRepository(connectionString);
userRepository.InitializeSchema();

builder.Services.AddSingleton(userRepository);
builder.Services.AddSingleton<InputValidator>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// Serve webform.html at root if not caught by static files
app.MapGet("/", async context =>
{
    var htmlPath = Path.Combine(app.Environment.ContentRootPath, "../../webform.html");
    if (!File.Exists(htmlPath))
    {
        htmlPath = Path.Combine(AppContext.BaseDirectory, "webform.html");
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

// Secure submission endpoint with input validation and parameterized storage
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

// Secure lookup endpoint using parameterized query
app.MapGet("/api/users/{username}", async (string username, UserRepository repository) =>
{
    var user = await repository.GetUserByUsernameAsync(username);
    return user is not null ? Results.Ok(user) : Results.NotFound();
});

app.Run();

// Partial class for integration test reference if needed
public partial class Program { }
