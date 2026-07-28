**AVG REGISTER**

**** 27 july 2026 10:07 ****

Creating new dpias isnt working, I am working on it. Fixed in 8P.

How to setup:

run .sql file to database in phpmyadmin.
Then point to 8p.php and edit the content with:

// Database Configuration
$db_config = [
    'host' => 'localhost',
    'username' => 'root',
    'password' => 'password',
    'database' => 'databasename',
    'charset' => 'utf8mb4'
];
