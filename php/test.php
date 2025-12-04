<?php
// This file contains examples of good and bad practices for SonarQube.
// Use this file when scanning with the SonarPHP analyzer to exercise common rules.
// SonarQube PHP test cases - examples of GOOD and BAD code to trigger rules.
// Use this file when scanning with the SonarPHP analyzer to exercise common rules
// such as SQL injection, XSS, hard-coded secrets, unused variables, complexity, etc.

declare(strict_types=1);

// BAD: Hard-coded credentials (should be flagged as a secret)
function bad_hardcoded_credentials(): array
{
	$dbHost = 'localhost';
	$dbUser = 'admin';
	$dbPass = 'P@ssw0rd'; // BAD: hard-coded secret
	return [$dbHost, $dbUser, $dbPass];
}

// GOOD: Load credentials from environment
function good_load_credentials(): array
{
	$dbHost = getenv('DB_HOST') ?: 'localhost';
	$dbUser = getenv('DB_USER') ?: 'postgres';
	$dbPass = getenv('DB_PASS') ?: '';
	return [$dbHost, $dbUser, $dbPass];
}

// BAD: SQL Injection via string concatenation
function bad_sql_injection(mysqli $conn, string $username): array
{
	$query = "SELECT * FROM users WHERE username = '" . $username . "'"; // vulnerable
	$result = $conn->query($query);
	return $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
}

// GOOD: Use prepared statements
function good_prepared_statement(mysqli $conn, string $username): array
{
	$stmt = $conn->prepare('SELECT * FROM users WHERE username = ?');
	$stmt->bind_param('s', $username);
	$stmt->execute();
	$res = $stmt->get_result();
	return $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
}

// BAD: Cross-site scripting (XSS) - unsanitized output
function bad_xss(): void
{
	$name = $_GET['name'] ?? 'guest';
	echo "Hello " . $name; // unsanitized output
}

// GOOD: Prevent XSS using escaping
function good_xss(): void
{
	$name = $_GET['name'] ?? 'guest';
	echo 'Hello ' . htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// BAD: Empty catch swallows exceptions
function bad_empty_catch(): void
{
	try {
		throw new Exception('oops');
	} catch (Exception $e) {
		// swallowed - bad practice
	}
}

// GOOD: Log and rethrow or handle properly
function good_exception_handling(): void
{
	try {
		throw new Exception('oops');
	} catch (Exception $e) {
		error_log('Exception: ' . $e->getMessage());
		throw $e;
	}
}

// BAD: Unused variable should be flagged
function bad_unused_variable(): bool
{
	$unused = 123; // unused variable
	return true;
}

// BAD: Duplicate code - two functions that do the same thing
function duplicate_one(): int
{
	$a = 1;
	$b = 2;
	return $a + $b;
}

function duplicate_two(): int
{
	$a = 'asdasd';
	$b = 2;
	return $a + $b;
}

// Function with higher cognitive complexity
function complex_logic(int $x): int
{
	if ($x < 0) {
		for ($i = 0; $i < 5; $i++) {
			if ($i % 2 === 0) {
				while ($x < 0) {
					if ($x === -10) {
						return -10;
					}
					$x++;
				}
			} else {
				switch ($i) {
					case 1:
					case 3:
						$x += $i;
						break;
					default:
						$x -= $i;
				}
			}
		}
	} elseif ($x === 0) {
		return 0;
	} else {
		$res = 0;
		for ($i = 0; $i < $x; $i++) {
			$res += $i;
		}
		return $res;
	}
	return $x;
}

// Small CLI runner to avoid accidental execution on web servers
if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['argv'][0])) {
	echo "SonarQube PHP test file\n";
	echo "- Demonstrating good/bad examples for scanning.\n";
}

duplicate_one();
duplicate_two();

// --- Errores intencionales para que SonarQube los marque ---

// BAD: eval on user input (remote code execution)
function bad_eval_user_input(): void
{
	$code = $_GET['code'] ?? '';
	// Intentional insecure pattern for testing Sonar rules
	eval($code);
}

// BAD: unserialize on user input (object injection)
function bad_unserialize_user(): void
{
	$data = $_POST['data'] ?? '';
	$obj = unserialize($data);
	// use $obj to avoid unused-variable warning
	if ($obj) {
		// do nothing
	}
}

// BAD: shell_exec with user input (command injection)
function bad_shell_exec(): void
{
	$cmd = $_GET['cmd'] ?? 'whoami';
	shell_exec($cmd);
}

// BAD: dynamic include from user input (file inclusion)
function bad_include_user(): void
{
	$page = $_GET['page'] ?? 'default';
	include __DIR__ . '/' . $page . '.php';
}

// BAD: weak hashing (md5) for passwords
function bad_md5_hash(string $password): string
{
	return md5($password);
}

// BAD: base64 decode then eval (obfuscated execution)
function bad_base64_eval(): void
{
	$p = $_GET['p'] ?? '';
	$payload = base64_decode($p);
	eval($payload);
}

// BAD: insecure randomness for token generation
function bad_insecure_random(): string
{
	return (string) mt_rand();
}

// BAD: fopen with user-controlled path (directory traversal)
function bad_file_open_user(): void
{
	$file = $_GET['file'] ?? '/etc/passwd';
	$h = @fopen($file, 'r');
	if ($h) {
		fclose($h);
	}
}

// BAD: assert with user input
function bad_assert_user_input(): void
{
	$a = $_GET['assert'] ?? '1 == 1';
	assert($a);
}

// BAD: preg_replace with /e modifier (deprecated/insecure)
function bad_preg_replace_e(): string
{
	$input = "hello";
	// This pattern uses /e intentionally (may cause warnings on new PHP versions)
	return preg_replace('/(h)/e', 'strtoupper("$1")', $input);
}

// End of intentional errors
