# SafeVault

A secure web application designed to manage sensitive user data and credentials, built as part of the Microsoft Full Stack Developer Specialization (Course 8: *Security and Authentication* Capstone Project).

SafeVault demonstrates defense-in-depth secure coding principles, focusing on the mitigation of common web application vulnerabilities including SQL Injection (SQLi) and Cross-Site Scripting (XSS).

**Live Interactive Deployment:** [https://jdsaire.github.io/fullstack_c8_safevault/](https://jdsaire.github.io/fullstack_c8_safevault/)  
*(Interact with the real-time input validation pipeline, parameterized SQL query inspector, and vulnerability attack simulator directly in your browser).*

---

## Architecture & Security Implementation

### 1. Input Validation and Sanitization
- **Web Form (`webform.html`)**: Features HTML5 validation constraints (`required`, length boundaries, and regex patterns restricting usernames to safe alphanumeric, underscore, hyphen, and period characters) alongside client-side sanitization routines that strip dangerous script tags and event handlers prior to submission.
- **Validation Service (`src/SafeVault/Services/InputValidator.cs`)**: Server-side defensive boundary enforcing strict structural validation and HTML entity encoding (`WebUtility.HtmlEncode`) to neutralize stored and reflected XSS payloads.

### 2. Parameterized Database Queries
- **Schema (`database.sql`)**: Defines the relational structure for user records (`Users` table).
- **Data Access (`src/SafeVault/Data/UserRepository.cs`)**: All database operations utilize parameterized commands (`SqliteParameter`) with SQLite. User-supplied parameters are bound explicitly as literal values, preventing any interpretation of malicious input as executable SQL logic.

### 3. Automated Vulnerability Testing
- **NUnit Test Fixture (`Tests/TestInputValidation.cs`)**:
  - `TestForSQLInjection()`: Simulates SQL injection attempts (tautologies, stacked queries, inline comments, union attacks) against the data access layer, verifying that parameters are strictly treated as data and table integrity remains uncompromised.
  - `TestForXSS()`: Simulates script injection and malicious event handler attributes, verifying that the sanitization engine reliably neutralizes executable code.

---

## Project Structure

```
├── .gitignore
├── README.md
├── SafeVault.sln
├── database.sql
├── webform.html
├── src/
│   └── SafeVault/
│       ├── Data/
│       │   └── UserRepository.cs
│       ├── Models/
│       │   └── UserSubmission.cs
│       ├── Services/
│       │   └── InputValidator.cs
│       ├── Program.cs
│       └── SafeVault.csproj
└── Tests/
    ├── TestInputValidation.cs
    └── Tests.csproj
```

---

## Build and Test Execution

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build Solution
```bash
dotnet build SafeVault.sln -c Release
```

### Run Vulnerability Tests
```bash
dotnet test --logger "console;verbosity=detailed"
```

All unit tests execute against an isolated in-memory database to verify security controls under simulated attack scenarios.

---

## AI Assistance Disclosure

*This section provides transparent disclosure of tool usage in accordance with the capstone evaluation criteria (Criteria C2, C5, and C6).*

During the development of SafeVault Activity 1, an AI environment was utilized to support secure design and testing:
1. **Input Validation and Sanitization (Criterion C2)**: An AI environment assisted in refining regular expression patterns and structuring the dual-stage sanitization pipeline to neutralize Cross-Site Scripting (XSS) vectors across form fields.
2. **SQL Injection Prevention (Criterion C2)**: An AI environment assisted in designing parameterized query structures, verifying placeholder bindings (`SqliteParameter`), and ensuring that user inputs are never concatenated directly into SQL command strings.
3. **Security Test Formulation (Criterion C5)**: An AI environment assisted in compiling realistic attack payloads (including tautologies, batch query terminations, inline comments, and script execution tags) for the automated NUnit test fixture (`Tests/TestInputValidation.cs`) to verify that the application blocks unauthorized access and data corruption.
