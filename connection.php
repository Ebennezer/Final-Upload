<?php

function getConnection() {
  $servername = "localhost";
  $dbname = "project";
  $username = "Team10user";
  $password="SOFTDEVpass123##";
  
  $conn = mysqli_connect($servername, $username, $password, $dbname);
  if (!$conn) {
      die("Connection failed: " . mysqli_connect_error());
  }
  echo "<script>console.log('Connected to database');</script>";
  return $conn;
}
function test_input($data)
{
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}
function loginUser(string $email, string $password): array {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    $email = strtolower(trim($email));
    $password = (string)$password;

    if ($email === '' || $password === '') {
        return ['ok' => false, 'message' => 'Email and password are required.', 'user' => null];
    }

    $conn = getConnection();

    try {
        $sql = "SELECT user_id, email, password_hash, role, empid, is_email_verified
                FROM users
                WHERE email = ?
                LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows !== 1) {
            $stmt->free_result();
            $stmt->close();
            return ['ok' => false, 'message' => 'Invalid email or password.', 'user' => null];
        }

        $stmt->bind_result($userId, $dbEmail, $dbHash, $role, $empid, $isVerified);
        $stmt->fetch();
        $stmt->free_result();
        $stmt->close();

        // Password check
        if (!password_verify($password, $dbHash)) {
            return ['ok' => false, 'message' => 'Invalid email or password.', 'user' => null];
        }

        // Email verification check
        if ((int)$isVerified !== 1) {
            return ['ok' => false, 'message' => 'Please verify your email before logging in.', 'user' => null];
        }

        // Successful login: store session
        session_regenerate_id(true);

        $_SESSION['user_id'] = (int)$userId;
        $_SESSION['email']   = (string)$dbEmail;
        $_SESSION['role']    = (string)$role;
        $_SESSION['empid']   = $empid !== null ? (int)$empid : null;
        $_SESSION['logged_in'] = true;

        $user = [
            'user_id' => (int)$userId,
            'email' => (string)$dbEmail,
            'role' => (string)$role,
            'empid' => $empid !== null ? (int)$empid : null,
            'is_email_verified' => (int)$isVerified
        ];

        return ['ok' => true, 'message' => 'Login successful.', 'user' => $user];

    } catch (Throwable $e) {
        error_log("loginUser error: " . $e->getMessage());
        return ['ok' => false, 'message' => 'Server error during login.', 'user' => null];
    } finally {
        if ($conn) { $conn->close(); }
    }
}
if (isset($_POST['loginBtn'])) {
    $res = loginUser($_POST['username'] ?? '', $_POST['password'] ?? '');

    if ($res['ok']) {
        // redirect based on role
        if ($_SESSION['role'] === 'admin') {
            header("Location: admin/admin.php");
        } else {
            header("Location: employee/employee.php");
        }
        exit;
    } else {
        echo "<script>alert(" . json_encode($res['message']) . "); window.history.back();</script>";
        exit;
    }
}

header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Expires: Sat, 01 Jan 2000 00:00:00 GMT");
?>