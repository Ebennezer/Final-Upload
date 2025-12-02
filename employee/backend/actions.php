<?php
require __DIR__ . '/../../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$mail = new PHPMailer(true);



//variables to store form data and error messages
$name      = isset($_POST['name']) ? $_POST['name'] : '';
$email     = isset($_POST['email']) ? $_POST['email'] : '';
$phone     = isset($_POST['phone']) ? $_POST['phone'] : '';
$dept      = isset($_POST['dept']) ? $_POST['dept'] : '';
$oldpass   = isset($_POST['oldpass']) ? $_POST['oldpass'] : '';
$newpass   = isset($_POST['newpass']) ? $_POST['newpass'] : '';
$confpass  = isset($_POST['confpass']) ? $_POST['confpass'] : '';
$empid     = isset($_SESSION['empid']) ? $_SESSION['empid'] : '';
//$sql       = isset($_POST['sql']) ? $_POST['sql'] : (isset($_SESSION['sql']) ? $_SESSION['sql'] : '');

// Error messages
$emailErr= $phoneErr = $oldpassErr = $newpassErr = $confpassErr ="";


//functions to connect to the database and validate inputs
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
// Function to sanitize user input
function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}
// Function to send mail
function sendMail($to, $name, $subject, $text, $ctaUrl = 'http://localhost/SOFTDEV/index.php', $ctaText ='Open Dashboard') {
    // Create a new PHPMailer for each call
    $mail = new PHPMailer(true);

    try {
        // SMTP config
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'softdevteam10corp@gmail.com';
        $mail->Password   = 'hjgjipssexcvjcpo'; // Gmail app password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        // From / To
        $mail->setFrom('softdevteam10corp@gmail.com', 'Corporate');
        $mail->addAddress($to, $name);

        // Load HTML template
        $templatePath = __DIR__ . '/../../email.html';
        $html = file_get_contents($templatePath);

        if ($html === false) {
            // fallback if template missing
            $html = "<p>Hi {$name},</p><p>" . nl2br(htmlspecialchars($text, ENT_QUOTES, 'UTF-8')) . "</p>";
        } else {
            // Replace placeholders one by one
            $html = str_replace('{{NAME}}', $name, $html);
            $html = str_replace('{{TEXT}}', nl2br($text), $html);
            $html = str_replace('{{CTA_URL}}', $ctaUrl, $html);
            $html = str_replace('{{CTA_TEXT}}', $ctaText, $html);
        }

        // Email body
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $html;
        $mail->AltBody = strip_tags($text);

        $mail->send();
        echo "<script>console.log('Email sent successfully');</script>";
        return true;
    } catch (Exception $e) {
        error_log('Mail error: ' . $mail->ErrorInfo);
        echo "<script>console.log('Email failed: " . addslashes($mail->ErrorInfo) . "');</script>";
        return false;
    }
}
// ===================== EMAIL VERIFICATION HELPERS =====================

// Change this if your project base URL changes
if (!defined('APP_BASE_URL')) {
    define('APP_BASE_URL', 'http://localhost/SOFTDEV');
}

function buildVerifyUrl(int $userId, string $rawToken): string {
    return rtrim(APP_BASE_URL, '/') . "/verify_email.php?uid={$userId}&token={$rawToken}";
}

/**
 * Create / update the employee's user account.
 * Sets is_email_verified = 0 because we will require re-verification.
 * Returns user_id.
 */
function upsertEmployeeUser(mysqli $conn, int $empid, string $email, string $lastname): int {
    $role = 'employee';
    $tempPasswordPlain = $lastname . $empid; // your rule: lastname+empid
    $passwordHash = password_hash($tempPasswordPlain, PASSWORD_DEFAULT);

    $sql = "
        INSERT INTO users (email, password_hash, role, empid, is_email_verified)
        VALUES (?, ?, ?, ?, 0)
        ON DUPLICATE KEY UPDATE
            password_hash = VALUES(password_hash),
            role          = VALUES(role),
            empid         = VALUES(empid),
            is_email_verified = 0
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssi", $email, $passwordHash, $role, $empid);
    $stmt->execute();

    // Get the user_id for this employee
    $stmt2 = $conn->prepare("SELECT user_id FROM users WHERE empid = ? LIMIT 1");
    $stmt2->bind_param("i", $empid);
    $stmt2->execute();
    $stmt2->bind_result($userId);
    $stmt2->fetch();

    return (int)$userId;
}

/**
 * Generates a token, stores its SHA-256 hash in email_verifications, returns RAW token for the link.
 * Also "consumes" any previous unconsumed tokens for that same user.
 */
function createEmailVerificationToken(mysqli $conn, int $userId, int $ttlMinutes = 1440): string {
    $rawToken  = bin2hex(random_bytes(32));       // 64 hex chars
    $tokenHash = hash('sha256', $rawToken);       // stored in DB (char(64))
    $expiresAt = date('Y-m-d H:i:s', time() + ($ttlMinutes * 60));

    // Invalidate older tokens
    $stmtOld = $conn->prepare("UPDATE email_verifications SET consumed_at = NOW() WHERE user_id = ? AND consumed_at IS NULL");
    $stmtOld->bind_param("i", $userId);
    $stmtOld->execute();

    // Insert new token row
    $stmt = $conn->prepare("INSERT INTO email_verifications (user_id, token, expires_at, consumed_at) VALUES (?, ?, ?, NULL)");
    $stmt->bind_param("iss", $userId, $tokenHash, $expiresAt);
    $stmt->execute();

    return $rawToken;
}

/**
 * Called from verify_email.php when user clicks link.
 * Returns [bool ok, string message]
 */
function verifyEmailFromLink($userId, $rawToken): array {
    $userId = intval($userId);
    $rawToken = trim((string)$rawToken);

    if ($userId <= 0 || $rawToken === '') {
        return [false, 'Invalid verification link.'];
    }

    $conn = getConnection();
    $tokenHash = hash('sha256', $rawToken);

    // 1) SELECT token row (BUFFER IT + CLOSE IT!)
    $stmt = $conn->prepare("
        SELECT expires_at, consumed_at
        FROM email_verifications
        WHERE user_id = ? AND token = ?
        LIMIT 1
    ");
    $stmt->bind_param("is", $userId, $tokenHash);
    $stmt->execute();

    // This is the key part to avoid "commands out of sync"
    $stmt->store_result();

    if ($stmt->num_rows === 0) {
        $stmt->free_result();
        $stmt->close();
        return [false, 'Invalid verification link.'];
    }

    $stmt->bind_result($expiresAt, $consumedAt);
    $stmt->fetch();
    $stmt->free_result();
    $stmt->close(); // <-- MUST close before any next query

    if (!empty($consumedAt)) {
        return [true, 'Email already verified.'];
    }

    if (strtotime($expiresAt) < time()) {
        return [false, 'Verification link expired.'];
    }

    // 2) Do updates in a transaction
    $conn->begin_transaction();

    try {
        $stmt2 = $conn->prepare("
            UPDATE email_verifications
            SET consumed_at = NOW()
            WHERE user_id = ? AND token = ? AND consumed_at IS NULL
        ");
        $stmt2->bind_param("is", $userId, $tokenHash);
        $stmt2->execute();

        if ($stmt2->affected_rows !== 1) {
            $stmt2->close();
            $conn->rollback();
            return [false, 'Link already used.'];
        }
        $stmt2->close();

        $stmt3 = $conn->prepare("UPDATE users SET is_email_verified = 1 WHERE user_id = ?");
        $stmt3->bind_param("i", $userId);
        $stmt3->execute();
        $stmt3->close();

        $conn->commit();
        return [true, 'Email verified successfully.'];
    } catch (Throwable $e) {
        $conn->rollback();
        return [false, 'Verification failed: ' . $e->getMessage()];
    }
}

/**
 * Login by email + password against users table.
 * - Uses password_verify() (so password_hash must be created with password_hash()).
 * - Blocks login if email not verified.
 * - On success, sets session variables.
 *
 * Returns: ['ok'=>bool, 'message'=>string, 'user'=>array|null]
 */
// Function to fill form for update employee
function fillinfo() {
    global $empid;

    // Resolve empid (GET eid takes priority, otherwise session)
    if (isset($_GET['eid'])) {
        $decoded = base64_decode($_GET['eid'], true);
        if ($decoded === false || !ctype_digit($decoded)) {
            die("Invalid employee identifier");
        }
        $empid = (int)$decoded;
        $_SESSION['empid'] = $empid;
    } elseif (isset($_SESSION['empid'])) {
        $empid = (int)$_SESSION['empid'];
    } else {
        die("Missing employee identifier");
    }

    $conn = getConnection();

    $sql = "
        SELECT 
            e.fname        AS Fname,
            e.lname        AS Lastname,
            e.email_work   AS Email,
            e.phone        AS Phone,
            e.division_id  AS DepartmentId,
            u.password_hash AS PasswordHash
        FROM employees e
        LEFT JOIN users u ON u.empid = e.empid
        WHERE e.empid = ?
        LIMIT 1
    ";

    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $empid);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = ($res && $res->num_rows > 0) ? $res->fetch_assoc() : null;

    $stmt->close();
    $conn->close();

    if (!$row) {
        die("Employee not found");
    }

    return [
        'firstname'     => isset($_POST['firstname']) ? test_input($_POST['firstname']) : $row['Fname'],
        'lastname'      => isset($_POST['lastname'])  ? test_input($_POST['lastname'])  : $row['Lastname'],
        'full_name'     => trim(
            (isset($_POST['firstname']) ? test_input($_POST['firstname']) : $row['Fname']) . ' ' .
            (isset($_POST['lastname'])  ? test_input($_POST['lastname'])  : $row['Lastname'])
        ),
        'email'         => isset($_POST['email']) ? test_input($_POST['email']) : $row['Email'],
        'phone'         => isset($_POST['phone']) ? test_input($_POST['phone']) : $row['Phone'],
        'department_id' => isset($_POST['department_id']) ? (int)$_POST['department_id'] : (int)$row['DepartmentId'],
        'password_hash' => $row['PasswordHash'],
        'empid'         => $empid,
    ];
}


function logout() {
    // Unset all session variables
    $_SESSION = [];

    // Destroy the session
    session_destroy();

    // Redirect to login page
    header('Location: /SOFTDEV/index.php');
    exit();
}  
// Function to validate form inputs
function validateform(){
  $conn = getConnection();
  $formtest=true;
  global $empid;
  $empid = isset($_SESSION['empid']) ? $_SESSION['empid'] : '';
  //  User Info
  global $email, $phone, $oldpass, $newpass, $confpass;
  global $emailErr, $phoneErr, $oldpassErr, $newpassErr, $confpassErr;


  if ($_SERVER["REQUEST_METHOD"] == "POST") {
        
    //Check if email is empty or not
    if (empty($_POST["email"])) {
      $emailErr = "Email is required";
      $formtest = false;
    } else {
      $email = test_input($_POST["email"]);
      $sql = "SELECT * FROM employees WHERE email_work='$email'";
      $res = $conn->query($sql);
      if (!preg_match("/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/", $email)) {
        $emailErr = "Invalid email format";
        $formtest = false;
      } else if ($res->num_rows > 0 && $empid != $res->fetch_assoc()['empid']) {
        $emailErr = "Email already exists";
        $formtest = false;
      } else $email= test_input($_POST["email"]);
    }
    //Check if phone is empty or not
    if (empty($_POST["phone"])) {
      $phoneErr = "Number is required";
      $formtest = false;
    } else {
      $phone = test_input($_POST["phone"]);
      $sql = "SELECT * FROM employees WHERE phone='$phone'";
      $res = $conn->query($sql);
      if (!preg_match('/^[0-9]{3}-[0-9]{3}-[0-9]{4}$/', $phone)) {
        $phoneErr = "Invalid Number format";
        $formtest = false;
      } else if ($res->num_rows > 0 && $empid != $res->fetch_assoc()['empid']) {
        $phoneErr = "Number already exists";
        $formtest = false;
      } else $phone = test_input($_POST["phone"]);
    }
    //Check if state is empty or not
    if (empty($_POST["state"])) {
      $stateErr = "State is required";
      $formtest = false;
    } else $state = test_input($_POST["state"]);
    
    //Check if city is empty or not
    if (empty($_POST["city"])) {
      $cityErr = "City is required";
      $formtest = false;
    }  else {
      if (!preg_match("/^[a-zA-Z-' ]*$/", $firstname)) {
        $cityErr = "Only letters and white space allowed";
        $formtest = false;
      } else $city = test_input($_POST["firstname"]);
    }
    
    
   //Check if passwords are empty or not
   if (!empty($_POST["oldpass"]) || !empty($_POST["newpass"]) || !empty($_POST["confpass"])) {
      // Validate old password
      if (empty($_POST["oldpass"])) {
          $oldpassErr = "Old password is required";
          $formtest = false;
      } else {
          $oldpass = test_input($_POST["oldpass"]);
          // Fetch current password hash from database
          $sql = "SELECT u.password_hash FROM users u JOIN employees e ON u.empid = e.empid WHERE e.empid = '$empid'";
          $result = $conn->query($sql);
          if ($result && $result->num_rows > 0) {
              $row = $result->fetch_assoc();
              if (!password_verify($oldpass, $row['password_hash'])) {
                  $oldpassErr = "Old password is incorrect";
                  $formtest = false;
              }
          } else {
              $oldpassErr = "User not found";
              $formtest = false;
          }
      }

      // Validate new password
      if (empty($_POST["newpass"])) {
          $newpassErr = "New password is required";
          $formtest = false;
      } else {
          $newpass = test_input($_POST["newpass"]);
          if (strlen($newpass) < 8) {
              $newpassErr = "New password must be at least 8 characters long";
              $formtest = false;
          }
      }

      // Validate confirm password
      if (empty($_POST["confpass"])) {
          $confpassErr = "Please confirm your new password";
          $formtest = false;
      } else {
          $confpass = test_input($_POST["confpass"]);
          if ($newpass !== $confpass) {
              $confpassErr = "Passwords do not match";
              $formtest = false;
          }
      }
   }
  }
  return $formtest;
 
}

// Function to update employee
function updatedetails() {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    $empid = isset($_SESSION['empid']) ? (int)$_SESSION['empid'] : 0;
    if ($empid <= 0) {
        echo "<script>alert('Missing employee session. Please log in again.'); window.location.href='/SOFTDEV/index.php';</script>";
        exit;
    }

    // Only validate what Profile form sends
    global $emailErr, $phoneErr;
    $emailErr = $phoneErr = "";
    $ok = true;

    $email = isset($_POST['email']) ? test_input($_POST['email']) : '';
    $phone = isset($_POST['phone']) ? test_input($_POST['phone']) : '';

    if ($email === '' || !preg_match("/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/", $email)) {
        $emailErr = "Valid email is required";
        $ok = false;
    }
    if ($phone === '') {
        $phoneErr = "Phone is required";
        $ok = false;
    }

    if (!$ok) return;

    $conn = getConnection();
    $conn->begin_transaction();

    try {
        // Update employees
        $stmt = $conn->prepare("UPDATE employees SET email_work = ?, phone = ? WHERE empid = ?");
        $stmt->bind_param("ssi", $email, $phone, $empid);
        $stmt->execute();
        $stmt->close();

        // Keep users email synced
        $stmt2 = $conn->prepare("UPDATE users SET email = ? WHERE empid = ?");
        $stmt2->bind_param("si", $email, $empid);
        $stmt2->execute();
        $stmt2->close();

        $conn->commit();

        echo "<script>alert('Profile updated successfully!'); window.location.href='setting.php';</script>";
        exit;

    } catch (Throwable $e) {
        $conn->rollback();
        error_log("updatedetails error: " . $e->getMessage());
        echo "<script>alert('Update failed. Check server logs.'); window.history.back();</script>";
        exit;
    } finally {
        $conn->close();
    }
}


function updatepassword() {
    global $oldpassErr, $newpassErr, $confpassErr;
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    $empid = isset($_SESSION['empid']) ? (int)$_SESSION['empid'] : 0;
    if ($empid <= 0) {
        echo "<script>alert('Missing employee session. Please log in again.'); window.location.href='/SOFTDEV/index.php';</script>";
        exit;
    }

    $oldpass = $_POST['oldpass'] ?? '';
    $newpass = $_POST['newpass'] ?? '';
    $confpass = $_POST['confpass'] ?? '';

    if ($oldpass === '' || $newpass === '' || $confpass === '') {
        $oldpassErr = $newpassErr = $confpassErr = "All password fields are required.";
        return;
    }
    if (strlen($newpass) < 8) {
        $newpassErr = "New password must be at least 8 characters long.";
        return;
    }
    if ($newpass !== $confpass) {
        $confpassErr = "New password and confirmation do not match.";
        return;
    }

    $conn = getConnection();

    // fetch current hash
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE empid = ? LIMIT 1");
    $stmt->bind_param("i", $empid);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$row || !password_verify($oldpass, $row['password_hash'])) {
        $conn->close();
        return $oldpassErr = "Old password is incorrect.";
    }

    $newHash = password_hash($newpass, PASSWORD_DEFAULT);

    $stmt2 = $conn->prepare("UPDATE users SET password_hash = ? WHERE empid = ?");
    $stmt2->bind_param("si", $newHash, $empid);
    $ok = $stmt2->execute();
    $stmt2->close();
    $conn->close();

    if ($ok) {
        echo "<script>alert('Password updated successfully!'); window.location.href='setting.php';</script>";
    } else {
        echo "<script>alert('Failed to update password.'); window.history.back();</script>";
    }
    exit;
}

// Function to list payroll
function viewpayroll(){
  $conn = getConnection();

  // Get divisions for filter dropdown
  $divisions = [];
  $divSql = "SELECT division_id, name FROM divisions ORDER BY name";
  $divRes = mysqli_query($conn, $divSql);
  if ($divRes) {
      while ($row = mysqli_fetch_assoc($divRes)) {
          $divisions[] = $row;
      }
      mysqli_free_result($divRes);
  }

  // Get payroll data joined with employees + divisions
  $sql = "
    SELECT 
        p.payroll_id,
        p.empid,
        e.fname AS First_Name,
        e.lname AS Last_Name,
        jt.name AS Job_Title,
        d.Name AS Division,
        p.period_month,
        p.gross_pay,
        p.taxes_withheld,
        p.deductions,
        p.net_pay,
        p.issued_at,
        p.notes
    FROM payroll p
    INNER JOIN employees e ON e.empid = p.empid
    LEFT JOIN job_titles jt ON e.job_title_id = jt.job_title_id
    LEFT JOIN divisions d ON e.division_id = d.division_id
    ";
    //ORDER BY p.period_month DESC, d.name ASC, e.lname ASC, e.fname ASC

  $result = $conn->query($sql);
  // Check connection
  if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
  }
  $rowcount = $result->num_rows;
  if ($result->num_rows > 0) {
      while ($row = $result->fetch_assoc()) {
          echo "<tr>
                  <td>{$row['empid']}</td>
                  <td>{$row['First_Name']}</td>
                  <td>{$row['Last_Name']}</td>
                  <td>{$row['Job_Title']}</td>
                  <td>{$row['Division']}</td>
                  <td>{$row['period_month']}</td>
                  <td>{$row['gross_pay']}</td>
                  <td>{$row['taxes_withheld']}</td>
                  <td>{$row['deductions']}</td>
                  <td>{$row['net_pay']}</td>
                  <td>{$row['issued_at']}</td>
                  <td>{$row['notes']}</td>
                </tr>";
      }
    }

  $payrollRows   = [];
  $totalGross    = 0;
  $totalNet      = 0;

  if ($result) {
      while ($row = mysqli_fetch_assoc($result)) {
          $payrollRows[] = $row;
          $totalGross += (float)$row['gross_pay'];
          $totalNet   += (float)$row['net_pay'];
      }
      mysqli_free_result($result);
  }

  $totalRecords = count($payrollRows);
  
}

// Main action router
if ($_SERVER["REQUEST_METHOD"] == "POST") {
   if (isset($_POST['logout'])) {
    logout();
  } else if (isset($_POST['updatedetails'])) {
    updatedetails();
  } else if (isset($_POST['updatepassword'])) {
    updatepassword();
  } 
  
}    

