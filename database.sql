-- database.sql
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL,
    PasswordHash VARCHAR(255) NOT NULL DEFAULT '',
    Role VARCHAR(32) NOT NULL DEFAULT 'User',
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON Users(Username);
CREATE INDEX idx_users_role ON Users(Role);
