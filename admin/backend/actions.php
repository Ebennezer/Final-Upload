<?php
require __DIR__ . '/../../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$mail = new PHPMailer(true);


// ===================== TEST SHIM (safe for production) =====================
// Provide a router *only during tests* so PHPUnit can call run_actions().
if (defined('TEST_MODE') && !function_exists('run_actions')) {
    function run_actions(): void {
        // Use any DB injected by tests; if not set, you can ignore $db here.
        $action = $_REQUEST['action'] ?? '';
        $role   = $_SESSION['role'] ?? '';

        switch ($action) {
            case 'page':  // RBAC guard: used by RBACTest
                if ($role !== 'Admin') {
                    http_response_code(403);
                    header('Content-Type: application/json');
                    echo json_encode([
                        'error'    => 'ACCESS_DENIED',
                        'redirect' => '/employee/employee.php',
                        'audit'    => ['event' => 'RBAC_DENIED']
                    ]);
                } else {
                    http_response_code(200);
                    header('Content-Type: application/json');
                    echo json_encode(['status' => 'OK']);
                }
                break;

            // Add more cases later if you want to run the other tests without changing your app:
            // case 'searchEmployees': ...
            // case 'createEmployee': ...
            // etc.

            default:
                http_response_code(400);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Unknown action']);
        }
    }
}
// =================== END TEST SHIM (safe for production) ===================

//variables to store form data and error messages
$firstname = isset($_POST['firstname']) ? $_POST['firstname'] : '';
$lastname  = isset($_POST['lastname']) ? $_POST['lastname'] : '';
$birthdate = isset($_POST['birthdate']) ? $_POST['birthdate'] : '';
$ssn       = isset($_POST['ssn']) ? $_POST['ssn'] : '';
$race      = isset($_POST['race']) ? $_POST['race'] : '';
$email     = isset($_POST['testemail']) ? $_POST['testemail'] : '';
$state     = isset($_POST['state']) ? $_POST['state'] : '';
$city      = isset($_POST['city']) ? $_POST['city'] : '';
$zipcode   = isset($_POST['zipcode']) ? $_POST['zipcode'] : '';
$gender    = isset($_POST['gender']) ? $_POST['gender'] : '';
$phone     = isset($_POST['phone']) ? $_POST['phone'] : '';
$address   = isset($_POST['address']) ? $_POST['address'] : '';
$address2  = isset($_POST['address2']) ? $_POST['address2'] : '';
$jobtitle  = isset($_POST['jobtitle']) ? $_POST['jobtitle'] : '';
$salary    = isset($_POST['salary']) ? $_POST['salary'] : '';
$hiredate  = isset($_POST['hiredate']) ? $_POST['hiredate'] : '';
$division  = isset($_POST['division']) ? $_POST['division'] : '';
$paydate1  = isset($_POST['paydate1']) ? $_POST['paydate1'] : '';
$paydate2  = isset($_POST['paydate2']) ? $_POST['paydate2'] : '';
$salary1   = isset($_POST['salary1']) ? $_POST['salary1'] : '';
$salary2   = isset($_POST['salary2']) ? $_POST['salary2'] : '';
$empid1    = isset($_POST['empid1']) ? $_POST['empid1'] : '';
$empid2    = isset($_POST['empid2']) ? $_POST['empid2'] : '';
$report    = isset($_POST['report']) ? $_POST['report'] : '';
$rate      = isset($_POST['rate']) ? $_POST['rate'] : '';
$empid     = isset($_POST['empid']) ? intval($_POST['empid']) : (isset($_SESSION['employeeid']) ? intval($_SESSION['employeeid']) : 0);
$sql       = isset($_POST['sql']) ? $_POST['sql'] : (isset($_SESSION['sql']) ? $_SESSION['sql'] : '');

// Error messages
$firstnameErr = $lastnameErr = $birthdateErr = $ssnErr = $raceErr = $emailErr = $stateErr = $cityErr  = $genderErr = $phoneErr = $addressErr = $address2Err =$zipcodeErr="";
$jobtitleErr = $salaryErr = $hiredateErr = $divisionErr = $empidErr = $searchErr ="";
$reportErr = $paydateErr = $paydate2 = $salary1Err = $rateErr = "";

//functions to connect to the database and validate inputs
function getConnection() {
  $servername = "localhost";
  $username = "Team10admin";
  $password = "Projectadmin";
  $dbname = "Project";
  
  $conn = mysqli_connect($servername, $username, $password, $dbname);
  if (!$conn) {
      die("Connection failed: " . mysqli_connect_error());
  }
  echo "<script>console.log('Connected to database');</script>";
  return $conn;
}
// Function to log out user
function logout() {
    // Unset all session variables
    $_SESSION = [];

    // Destroy the session
    session_destroy();

    // Redirect to login page
    header('Location: /SOFTDEV/index.php');
    exit();
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

function upsertAdminUser(mysqli $conn, int $userId, string $email, string $password): void {
    $role = 'admin';
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $sql = "
        INSERT INTO users (user_id, email, password_hash, role, empid, is_email_verified)
        VALUES (?, ?, ?, ?, NULL, 1)
        ON DUPLICATE KEY UPDATE
            email          = VALUES(email),
            password_hash  = VALUES(password_hash),
            role           = VALUES(role),
            is_email_verified = 1
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("isss", $userId, $email, $passwordHash, $role);
    $stmt->execute();
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
function fillform() {
  global $empid;
  if (!isset($_SESSION['employeeid']) && !isset($_GET['eid'])) {
      die("Missing employee identifier");
  }else if (isset($_GET['eid'])) {
      $encoded = $_GET['eid'];
      $decoded = base64_decode($encoded, true); // strict decode

      if ($decoded === false || !ctype_digit($decoded)) {
          die("Invalid employee identifier");
      }
       $empid = (int)$decoded;
  } 

  

 
  $conn = getConnection();
  //global $empid;
  // Make sure $empid is defined
  $_SESSION['employeeid'] = $empid; // Store empid in session for later use

  
  // Fetch employee data
 $sql = "
          SELECT 
              e.empid,
              e.fname      AS Fname,
              e.lname      AS Lastname,
              e.email_work AS Email,
              e.hired_at   AS HireDate,
              e.salary     AS Salary,
              e.ssn        AS SSN,
              e.gender     AS Gender,
              e.dob        AS DOB,
              e.race       AS Race,
              e.phone      AS Phone,
              a.line1      AS Street1,
              a.line2      AS Street2,
              a.city       AS City,
              a.state_code AS State,
              a.postal_code AS Zip,
              e.job_title_id AS Job_Title,
              e.division_id       AS Division
          FROM employees e
          LEFT JOIN addresses a ON e.address_id = a.address_id
          WHERE e.empid = '$empid'
      ";

  
  $result = $conn->query($sql);
  $row = $result && $result->num_rows > 0 ? $result->fetch_assoc() : null;
  
  // Use either $_POST (if form submitted) or fetched data (initial form load)
   //  User Info
  global $firstname, $lastname, $birthdate, $ssn, $race, $email, $state, $city, $zipcode, $gender, $phone, $address;
  //global $firstnameErr, $lnamelErr, $bdateErr, $ssnErr, $raceErr, $emailErr, $stateErr, $cityErr, $genderErr, $phoneErr, $addressErr, $zipcodeErr;
  

  //Job Info
  global $jobtitle,  $salary, $hiredate, $division;
  //global $jobtitleErr, $salaryErr, $hiredateErr, $divisionErr;
  if ($result && $result->num_rows > 0) {

  $firstname = isset($_POST['firstname']) ? test_input($_POST['firstname']) : $row['Fname'];
  $lastname  = isset($_POST['lastname'])  ? test_input($_POST['lastname'])  : $row['Lastname'];
  $birthdate = isset($_POST['birthdate']) ? test_input($_POST['birthdate']) : $row['DOB'];
  $ssn       = isset($_POST['ssn'])       ? test_input($_POST['ssn'])       : $row['SSN'];
  $race      = isset($_POST['race'])      ? test_input($_POST['race'])      : $row['Race'];
  $email     = isset($_POST['testemail']) ? test_input($_POST['testemail']) : $row['Email'];

  $state     = isset($_POST['state'])     ? test_input($_POST['state'])     : $row['State'];
  $city      = isset($_POST['city'])      ? test_input($_POST['city'])      : $row['City'];
  $zipcode   = isset($_POST['zipcode'])   ? test_input($_POST['zipcode'])   : $row['Zip'];
  $gender    = isset($_POST['gender'])    ? test_input($_POST['gender'])    : $row['Gender'];
  $phone     = isset($_POST['phone'])     ? test_input($_POST['phone'])     : $row['Phone'];
  $address   = isset($_POST['address'])   ? test_input($_POST['address'])   : $row['Street1'];
  $address2  = isset($_POST['address2'])  ? test_input($_POST['address2'])  : $row['Street2'];

  $jobtitle  = isset($_POST['jobtitle'])  ? test_input($_POST['jobtitle'])  : $row['Job_Title'];
  $salary    = isset($_POST['salary'])    ? test_input($_POST['salary'])    : $row['Salary'];
  $hiredate  = isset($_POST['hiredate'])  ? test_input($_POST['hiredate'])  : $row['HireDate'];
  $division  = isset($_POST['division'])  ? test_input($_POST['division'])  : $row['Division'];

  
  }

  
}  
// Function to fill user info
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
// Function to validate form inputs
function validateform(){
  $conn = getConnection();
  $formtest=true;
  global $empid;
  $empid = isset($_POST['empid']) ? intval($_POST['empid']) : (isset($_SESSION['employeeid']) ? intval($_SESSION['employeeid']) : 0);
  //  User Info
  global $firstname, $lastname, $birthdate, $ssn, $race, $email, $state, $city, $zipcode, $gender, $phone, $address, $address2;
  global $firstnameErr, $lastnameErr, $birthdateErr, $ssnErr, $raceErr, $emailErr, $stateErr, $cityErr, $genderErr, $phoneErr, $addressErr, $address2Err, $zipcodeErr;
  

  //Job Info
  global $jobtitle,  $salary, $hiredate, $division;
  global $jobtitleErr, $salaryErr, $hiredateErr, $divisionErr;

  if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    //Check if first name is empty or not
    if (empty($_POST["firstname"])) {
      $firstnameErr = "First Name is required";
      $formtest = false;
    } else {
      if (!preg_match("/^[a-zA-Z-' ]*$/", $firstname)) {
        $firstnameErr = "Only letters and white space allowed";
        $formtest = false;
      } else $firstname = test_input($_POST["firstname"]);
    }
    //Check if last name is empty or not
    if (empty($_POST["lastname"])) {
      $lastnameErr = "Last Name is required";
      $formtest = false;
    } else {
      if (!preg_match("/^[a-zA-Z-' ]*$/", $lastname)) {
        $lastnameErr = "Only letters and white space allowed";
        $formtest = false;
      } else $lastname = test_input($_POST["lastname"]);
    }
    //Check if birthdate is empty or not
    if (empty($_POST["birthdate"])) {
      $birthdateErr = "Birthdate is required";
      $formtest = false;
    } else {
      $birthdate = test_input($_POST["birthdate"]);
    }
    //Check if gender is empty or not
    if (empty($_POST["gender"])) {
      $genderErr = "Gender is required";
      $formtest = false;
    } else {
      $gender = test_input($_POST["gender"]);
    }
    //Check if ssn is empty or not
    if( empty($_POST["ssn"])) {
      $ssnErr = "SSN is required";
      $formtest = false;
    } else {
      $ssn = test_input($_POST["ssn"]);
      $sql = "SELECT * FROM employees WHERE SSN='$ssn'";
      $res = $conn->query($sql);
      if (!preg_match("/^\d{3}-\d{2}-\d{4}$/", $ssn)) {
        $ssnErr = "Invalid SSN format";
        $formtest = false;
      } else if ($res->num_rows > 0 && $empid != $res->fetch_assoc()['empid']) {
        $ssnErr = "SSN already exists";
        $formtest = false;
      } else $ssn = test_input($_POST["ssn"]);
    }
    //Check if race is empty or not
    if (empty($_POST["race"])) {
      $raceErr= "Race is required";
      $formtest = false;
    } else $race = test_input($_POST["race"]);

    //Check if email is empty or not
    if (empty($_POST["testemail"])) {
      $emailErr = "Email is required";
      $formtest = false;
    } else {
      $email = test_input($_POST["testemail"]);
      $sql = "SELECT * FROM employees WHERE email_work='$email'";
      $res = $conn->query($sql);
      if (!preg_match("/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/", $email)) {
        $emailErr = "Invalid email format";
        $formtest = false;
      } else if ($res->num_rows > 0 && $empid != $res->fetch_assoc()['empid']) {
        $emailErr = "Email already exists";
        $formtest = false;
      } else $email= test_input($_POST["testemail"]);
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
    
    
    //Check if zipcode is empty or not
    if(empty($_POST["zipcode"])){
      $zipcodeErr = "Zipcode is required";
      $formtest = false;
    }else{
      if (!preg_match("/^[0-9]{5}$/", $_POST["zipcode"])) {
        $zipcodeErr = "Invalid zipcode format";
        $formtest = false;
      } else $zipcode = test_input($_POST["zipcode"]);
    }
    //Check if address1 is empty or not
    if (empty($_POST["address"])) {
      $addressErr = "Address is required";
      $formtest = false;
    }else{
      if (!preg_match("/^[a-zA-Z0-9-' ]*$/", $_POST["address"])) {
        $addressErr = "Only letters and white space allowed";
        $formtest = false;
      } else $address = test_input($_POST["address"]);
    }
    //Check if address2 is empty or not
    if(!empty($_POST["address2"])){
      if (!preg_match("/^[a-zA-Z0-9-' ]*$/", $_POST["address2"])) {
        $address2Err = "Only letters and white space allowed";
        $formtest = false;
      } else $address2 = test_input($_POST["address2"]);
    }
    //Check if job title is empty or not
    if (empty($_POST["jobtitle"])) {
      $jobtitleErr = "Job title is required";
      $formtest = false;
    }  else $jobtitle = test_input($_POST["jobtitle"]);
    //Check if division is empty or not
    if (empty($_POST["division"])) {
      $divisionErr = "Division is required";
      $formtest = false;
    } else $division = test_input($_POST["division"]);
    //Check if hire date is empty or not
    if (empty($_POST["hiredate"])) {
      $hiredateErr = "Hire date is required";
      $formtest = false;
    } else {
      $hiredate = test_input($_POST["hiredate"]);
    }
    //Check if Salary is empty or not
    if (empty($_POST["salary"])) {
      $salaryErr = "Salary is required";
      $formtest = false;
    } else {
      if (!preg_match("/^\d+(\.\d{1,2})?$/", $_POST["salary"])) {
        $salaryErr = "Invalid Salary format";
        $formtest = false;
      } else $salary = test_input($_POST["salary"]);
    }
  }
  return $formtest;
 
}
// Function to update details
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
// Function to update password
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
// Function to add employee
function addemployee() {
    $conn = getConnection();

    if (!validateform()) {
        return;
    }

    // =========================
    // Employee Info
    // =========================
    $firstname = test_input($_POST["firstname"]);
    $lastname  = test_input($_POST["lastname"]);
    $email     = test_input($_POST["testemail"]);
    $hiredate  = date('Y-m-d', strtotime($_POST["hiredate"]));
    $salary    = test_input($_POST["salary"]);
    $ssn       = test_input($_POST["ssn"]);

    // =========================
    // Address Info
    // =========================
    $address  = test_input($_POST["address"]);
    $city     = test_input($_POST["city"]);
    $state    = test_input($_POST["state"]);
    $zipcode  = test_input($_POST["zipcode"]);
    $gender   = test_input($_POST["gender"]);
    $race     = isset($_POST["race"]) ? test_input($_POST["race"]) : '';
    $phone    = test_input($_POST["phone"]);

    // Birthdate: allow empty and store NULL if not provided
    $birthdate = !empty($_POST["birthdate"])
        ? date('Y-m-d', strtotime($_POST["birthdate"]))
        : null;

    // =========================
    // Job / Division Info
    // =========================
    $jobtitle = test_input($_POST["jobtitle"]);   // job_title_id
    $division = test_input($_POST["division"]);   // division_id

    // ======================================
    // 1) Insert into ADDRESSES
    // ======================================
    $sql1 = "
        INSERT INTO addresses (line1, line2, city, state_code, postal_code)
        VALUES ('$address', '', '$city', '$state', '$zipcode')
    ";

    $success1 = mysqli_query($conn, $sql1);

    if (!$success1) {
        $err = mysqli_error($conn);
        echo "<script>
                alert('Failed to insert into addresses table.');
                console.error(" . json_encode($err) . ");
                window.history.back();
              </script>";
        return;
    }

    $addressId = mysqli_insert_id($conn);

    // ======================================
    // 2) Insert into EMPLOYEES (new schema)
    // ======================================

    // Handle NULL dob properly in SQL
    $dobValue = $birthdate ? "'" . $birthdate . "'" : "NULL";

    $sql2 = "
        INSERT INTO employees (
            fname,
            lname,
            email_work,
            hired_at,
            salary,
            ssn,
            gender,
            race,
            dob,
            phone,
            job_title_id,
            division_id,
            address_id
        )
        VALUES (
            '$firstname',
            '$lastname',
            '$email',
            '$hiredate',
            '$salary',
            '$ssn',
            '$gender',
            '$race',
            $dobValue,
            '$phone',
            '$jobtitle',
            '$division',
            '$addressId'
        )
    ";

    $success2 = mysqli_query($conn, $sql2);

    if ($success2) {
        $empid = mysqli_insert_id($conn); // if you need it later
        // ================================
        if($division == 1){
          // Create admin user
          $userId = upsertAdminUser($conn, $empid, $email, $lastname . $empid);
        }else{
          // 1) Create / update employee user
          $userId = upsertEmployeeUser($conn, $empid, $email, $lastname);
        }

          // 2) Create verification token + link
          $rawToken = createEmailVerificationToken($conn, $userId);
          $verifyUrl = buildVerifyUrl($userId, $rawToken);
        // Generate a temporary password
        $tempPass = $lastname . $empid; // your rule: lastname+empid
        // Send welcome email with temporary password
        $text = "Your employee account has been created successfully.<br><br>"
          . "Temporary password: <b>{$tempPass}</b><br><br>"
          . "Please verify your email by clicking the button below (expires in 24 hours).<br><br>"
          . "Best regards,<br>HR Team";
        

        sendMail(
            $email,
            $firstname . ' ' . $lastname,
            'Welcome to the Company',
            $text,$verifyUrl,'Verify Email'
        );
        echo "<script>
                alert('Employee added successfully.');
                window.location.href = './employee.php';
                console.log('SQL Script: ' + " . json_encode($sql1 . "\n" . $sql2) . ");
                console.log('Email sent to: ' + " . json_encode($email) . ");
              </script>";
        
    } else {
        $err = mysqli_error($conn);
        echo "<script>
                alert('Failed to insert into employees table.');
                console.error(" . json_encode($err) . ");
                window.history.back();
              </script>";
    }
    
}
// Function to update employee
function updateemployee() {
    global $empid;

    // Get empid from session (set in employeedetails.php)
    $empid = isset($_SESSION['employeeid']) ? intval($_SESSION['employeeid']) : 0;
    $empid = intval($empid);

    if ($empid <= 0) {
        echo "<script>
                alert('Missing or invalid employee ID.');
                window.history.back();
              </script>";
        return;
    }

    $conn = getConnection();

    // Run your existing validation
    if (!validateform()) {
        // keep empid so form can re-render with errors
        $empid = isset($_POST['empid']) ? intval($_POST['empid']) : $empid;
        return;
    }

    // =========================
    //  Gather & sanitize input
    // =========================

    // Employee Info
    $firstname = test_input($_POST["firstname"]);
    $lastname  = test_input($_POST["lastname"]);
    $email     = test_input($_POST["testemail"]);
    $hiredate  = date('Y-m-d', strtotime($_POST["hiredate"]));
    $salary    = test_input($_POST["salary"]);
    $ssn       = test_input($_POST["ssn"]);

    // Address Info
    $address  = test_input($_POST["address"]);
    $city     = test_input($_POST["city"]);
    $state    = test_input($_POST["state"]);
    $zipcode  = test_input($_POST["zipcode"]);
    $gender   = test_input($_POST["gender"]);
    $race     = isset($_POST["race"]) ? test_input($_POST["race"]) : '';
    $phone    = test_input($_POST["phone"]);

    // IMPORTANT: match your form field name: birthdate
    $birthdate = !empty($_POST["birthdate"])
        ? date('Y-m-d', strtotime($_POST["birthdate"]))
        : null;

    // Job / Division Info (IDs from <select>)
    $jobtitle = test_input($_POST["jobtitle"]);   // job_title_id
    $division = test_input($_POST["division"]);   // division_id

    // ==========================================
    //  Look up address_id for this employee
    // ==========================================
    $addressId = null;
    $addrRes = $conn->query("SELECT address_id FROM employees WHERE empid = $empid");

    if ($addrRes && $addrRes->num_rows > 0) {
        $addrRow  = $addrRes->fetch_assoc();
        $addressId = !empty($addrRow['address_id']) ? intval($addrRow['address_id']) : null;
    }

    // ==========================================
    //  Update EMPLOYEES table (new schema)
    // ==========================================

    // If you added a race column on employees, keep Race = '$race'.
    // If not, remove that line.
    $sql_emp = "
        UPDATE employees
        SET
            fname       = '$firstname',
            lname       = '$lastname',
            email_work  = '$email',
            hired_at    = '$hiredate',
            salary      = '$salary',
            ssn         = '$ssn',
            gender      = '$gender',
            " . ($birthdate ? "dob = '$birthdate'," : "") . "
            phone       = '$phone',
            job_title_id = '$jobtitle',
            division_id  = '$division'
            " . (!empty($race) ? ", race = '$race'" : "") . "
        WHERE empid = $empid
    ";

    $success_emp = mysqli_query($conn, $sql_emp);

    // ==========================================
    //  Update / Insert into ADDRESSES
    // ==========================================

    $success_addr = true; // default

    if ($addressId) {
        // Update existing address row
        $sql_addr = "
            UPDATE addresses
            SET
                line1       = '$address',
                line2       = '',
                city        = '$city',
                state_code  = '$state',
                postal_code = '$zipcode'
            WHERE address_id = $addressId
        ";
        $success_addr = mysqli_query($conn, $sql_addr);
    } else {
        // No address yet: insert & attach to employee
        $sql_addr_insert = "
            INSERT INTO addresses (line1, line2, city, state_code, postal_code, country)
            VALUES ('$address', '', '$city', '$state', '$zipcode', 'US')
        ";
        $success_addr = mysqli_query($conn, $sql_addr_insert);

        if ($success_addr) {
            $newAddressId = mysqli_insert_id($conn);
            $sql_link = "UPDATE employees SET address_id = $newAddressId WHERE empid = $empid";
            $success_addr = mysqli_query($conn, $sql_link);
        }
    }

    // ==========================================
    //  Final result handling
    // ==========================================

    if ($success_emp && $success_addr) {
        $text = 'Your employee account has been updated successfully. If you did not make these changes, please contact your system administrator immediately.<br><br>Best regards,<br>HR Team';
        sendMail(
          $email,
          $firstname . ' ' . $lastname,
          'Account Update Notification',
          $text
        );

        echo "<script>
                console.log('SQL Script: ' + " . json_encode($sql_emp . "\n" . ($addressId ? $sql_addr : $sql_addr_insert)) . ");
                console.log('Update employees: ' + " . json_encode($success_emp ? "Success" : "Failed") . ");
                console.log('Update addresses: ' + " . json_encode($success_addr ? "Success" : "Failed") . ");
                alert('Employee updated successfully!');
                window.location.href = './employee.php';
              </script>";
        unset($_SESSION['employeeid']);
    } else {
        $errorMessage = "Failed to update:\n";

        if (!$success_emp) {
            $errorMessage .= "- Employees table: " . mysqli_error($conn) . "\n";
        }
        if (!$success_addr) {
            $errorMessage .= "- Addresses table: " . mysqli_error($conn) . "\n";
        }

        echo "<script>
                alert(`$errorMessage`);
                window.history.back();
              </script>";
    }
}

// Function to delete employee
function terminateemployee($empid) {
    $conn  = getConnection();
    $empid = intval($empid);
    

    // 1) Look up employee so we can email them
    $sqlSelect = "
        SELECT 
            email_work AS email,
            fname,
            lname
        FROM employees
        WHERE empid = $empid
        LIMIT 1
    ";

    $res = mysqli_query($conn, $sqlSelect);

    if (!$res || mysqli_num_rows($res) === 0) {
        echo "<script>
                alert('Employee not found.');
                window.history.back();
              </script>";
        return;
    }

    $emp    = mysqli_fetch_assoc($res);
    $email  = $emp['email'];
    $name   = $emp['fname'] . ' ' . $emp['lname'];
    $today  = date('Y-m-d');

    // 2) Soft terminate: only set terminated_at
    $sqlUpdate = "
        UPDATE employees
        SET terminated_at = CURDATE()
        WHERE empid = $empid
    ";

    if (mysqli_query($conn, $sqlUpdate)) {

        // 3) Send termination email (ignore failure for UI, just log it)
        $text = "Dear {$name},\n\n"
              . "This email is to inform you that your employment with CityLink Live "
              . "has been terminated effective {$today}.\n\n"
              . "If you believe this is an error, please contact HR or your system administrator.\n\n"
              . "Best regards,\n"
              . "HR Team";

        // Use your existing HTML template mailer
        @sendMail(
            $email,
            $name,
            'Employment Termination Notice',
            $text,
            'http://localhost/SOFTDEV/index.php'
        );

        echo "<script>
                console.log(" . json_encode("Employee $empid terminated on {$today}") . ");
                alert('Employee terminated successfully!');
                window.location.href = './employee.php';
              </script>";
    } else {
        $err = mysqli_error($conn);
        echo "<script>
                alert('Error terminating employee: " . addslashes($err) . "');
                window.history.back();
              </script>";
    }

    mysqli_close($conn);
    unset($_SESSION['employeeid']);
}
// Function to list employees
function viewemployees(){
  $conn = getConnection();

  $sql = "
  SELECT 
      e.empid AS EmpID,
      e.Fname AS First_Name,
      e.Lname AS Last_Name,
      e.gender AS Gender,
      e.phone AS Phone,
      e.email_work AS Email,
      e.Salary AS Salary,
      jt.name AS Job_Title,
      d.Name AS Division,
      e.dob AS Birth_Date
  FROM employees e
  LEFT JOIN addresses a ON e.empid = a.empid
  LEFT JOIN job_titles jt ON e.job_title_id = jt.job_title_id
  LEFT JOIN divisions d ON e.division_id = d.division_id
  where e.terminated_at IS NULL
      ";  
  
  $result = $conn->query($sql);
  // Check connection
  if (!$conn) {
  die("Connection failed: " . mysqli_connect_error());
  }
  $rowcount = $result->num_rows;
  if ($result->num_rows > 0) {
      while ($row = $result->fetch_assoc()) {
          echo "<tr>
                  <td>{$row['EmpID']}</td>
                  <td>{$row['First_Name']}</td>
                  <td>{$row['Last_Name']}</td>
                  <td>{$row['Gender']}</td>
                  <td>{$row['Birth_Date']}</td>
                  <td>{$row['Phone']}</td>
                  <td>{$row['Email']}</td>
                  <td>{$row['Job_Title']}</td>
                  <td>{$row['Division']}</td>
                  <td>{$row['Salary']}</td>
                  
                </tr>";
      }
      echo "<script>
              console.log('SQL Script: ' + " . json_encode($sql) . ");
              console.log('Number of rows: ' + " . json_encode($rowcount) . ");
            </script>";


  } else {
      echo "<tr><td colspan='9'>No employees found</td></tr>";
  }
  
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
// Function to print the filter form for reports
function printreportfilter(){
  global $empid1, $empid2, $jobtitle, $division, $paydate1, $paydate2, $salary1, $salary2;
  global $empidErr, $jobetitleErr, $divisionErr, $paydateErr, $salaryErr;
  echo '
        <h2>Filter</h2>
        <label><span>Employee ID</span>
        <input type="text" id="empid" class="input_text" placeholder="1000 " name="empid1" value="' . $empid1 . '"/>
        <span>To</span>
        <input type="text" id="empid" class="input_text" placeholder="9999 " name="empid2" value="' . $empid2 . '"/>
        </label>' . (isset($empidErr) ? '<label class="form_error" style="color: red; font-size: 14px; width:100%; font-family:&quot;Oswald&quot;, sans-serif; float:right; text-align:right; padding:0 0 0px 20px;"> ' . $empidErr . '</label>' : '') . '
        <label><span>Job Title</span>
        <select name="jobtitle" id="jobtitle" >
            <option value=0>-select-</option>  
            <option value="100" ' . ($jobtitle == 100 ? "selected" : "") . '>Software Manager</option>
            <option value="101" ' . ($jobtitle == 101 ? "selected" : "") . '>Software Architect</option>
            <option value="102" ' . ($jobtitle == 102 ? "selected" : "") . '>Software Engineer</option>
            <option value="103" ' . ($jobtitle == 103 ? "selected" : "") . '>Software Developer</option>
            <option value="200" ' . ($jobtitle == 200 ? "selected" : "") . '>Marketing Manager</option>
            <option value="201" ' . ($jobtitle == 201 ? "selected" : "") . '>Marketing Associate</option>
            <option value="202" ' . ($jobtitle == 202 ? "selected" : "") . '>Marketing Assistant</option>
            <option value="900" ' . ($jobtitle == 900 ? "selected" : "") . '>Chief Exec. Officer</option>
            <option value="901" ' . ($jobtitle == 901 ? "selected" : "") . '>Chief Finn. Officer</option>
            <option value="902" ' . ($jobtitle == 902 ? "selected" : "") . '>Chief Info. Officer</option>
        </select>
        </label>' . (isset($jobetitleErr) ? '<label class="form_error" style="color: red; font-size: 14px; width:100%; font-family:&quot;Oswald&quot;, sans-serif; float:right; text-align:right; padding:0 0 0px 20px;"> ' . $jobetitleErr . '</label>' : '') . '
        <label><span> Division </span>
        <select name="division" id="division" class="input_text">
            <option value=0>-select-</option>
            <option value="1" ' . ($division == 1 ? "selected" : "") . '>Technology Engineering</option>
            <option value="2" ' . ($division == 2 ? "selected" : "") . '>Marketing</option>
            <option value="3" ' . ($division == 3 ? "selected" : "") . '>Human Resources</option>
            <option value="999" ' . ($division == 999 ? "selected" : "") . '>HQ</option>
        </select>
        </label>' . (isset($divisionErr) ? '<label class="form_error" style="color: red; font-size: 14px; width:100%; font-family:&quot;Oswald&quot;, sans-serif; float:right; text-align:right; padding:0 0 0px 20px;"> ' . $divisionErr . '</label>' : '') . '
        <label><span>Pay date</span>
        <input type="date" id="bdate" class="input_text" name="paydate1" placeholder="MM/DD/YYYY" value="' . $paydate1 . '" >
        <span>To</span>
        <input type="date" id="bdate" class="input_text" name="paydate2" placeholder="MM/DD/YYYY" value="' . $paydate2 . '" >
        </label>' . (isset($paydateErr) ? '<label class="form_error" style="color: red; font-size: 14px; width:100%; font-family:&quot;Oswald&quot;, sans-serif; float:right; text-align:right; padding:0 0 0px 20px;"> ' . $paydateErr . '</label>' : '') . '
        <label><span> Salary</span>
        <input type="text" id="salary" class="input_text" placeholder="10,000" name="salary1" value="' . $salary1 . '">
        <span>To</span>
        <input type="text" id="salary" class="input_text" placeholder="100,000" name="salary2" value="' . $salary2 . '">
        </label>' . (isset($salaryErr) ? '<label class="form_error" style="color: red; font-size: 14px; width:100%; font-family:&quot;Oswald&quot;, sans-serif; float:right; text-align:right; padding:0 0 0px 20px;"> ' . $salaryErr . '</label>' : '');

}
// Function to generate report
function generatereport(){
  $conn = getConnection();
  $test=true;
  global $report, $jobtitle, $salary1, $salary2, $paydate, $paydate2, $division, $sql,$empid1, $empid2;
  global $reportErr, $paydateErr, $salary1Err, $salaryErr, $empidErr;
  $row= isset($_GET['sort_column']) ? $_GET['sort_column'] : 'pay_date';
  $order= isset($_GET['sort_order']) ?$_GET['sort_order'] : 'DESC';
  $filter="WHERE (p.empid = e.empid)";

  if (empty($_POST["report"])) {
    $reportErr = "Report type is required";
    $test = false;
  }else if ($_POST["report"] == "3"){
    $report = test_input($_POST["report"]);
    
  } else if ($_POST["report"] == "2"){
    $report = test_input($_POST["report"]);
  } else if ($_POST["report"] == "1"){
    $report = test_input($_POST["report"]);
    if (!empty($_POST["empid1"])) {
      if (!preg_match("/^[1-9][0-9]{0,3}$/", $_POST["empid1"])) {
          $empidErr = "Invalid Employee ID format";
          $test = false;
      } else $empid1 = test_input($_POST["empid1"]);
      }
      if (!empty($_POST["empid2"])) {
          if (!preg_match("/^[1-9][0-9]{0,3}$/", $_POST["empid2"])) {
              $empidErr = "Invalid Employee ID format";
              $test = false;
          } else $empid2 = test_input($_POST["empid2"]);
      }

      if(!empty($_POST["empid1"] ) && empty($_POST["empid2"])){
        $filter .=" AND (e.empid >= '$empid1') ";
      } else if(empty($_POST["empid1"] ) && !empty($_POST["empid2"])){
        $filter .=" AND (e.empid <= '$empid2')";
      } else if(!empty($_POST["empid1"] ) && !empty($_POST["empid2"])){
          if ($empid1 > $empid2) {
              $test = false;
              $empidErr="Invalid Employee ID range"; 
          } else $filter .=" AND (e.empid BETWEEN '$empid1' AND '$empid2')";
      }

      if (!empty($_POST["paydate1"])) {
          $paydate1 = date('Y-m-d', strtotime($_POST["paydate1"]));   
      }
      if (!empty($_POST["paydate2"])) {
          $paydate2 = date('Y-m-d', strtotime($_POST["paydate2"]));
      }
      if (!empty($_POST["paydate1"]) && empty($_POST["paydate2"])) {
          $filter .=" AND (p.Pay_Date >= '$paydate1')";
      } else if (empty($_POST["paydate1"]) && !empty($_POST["paydate2"])) {
          $filter .=" AND (p.Pay_Date <= '$paydate2')";
      } else if(!empty($_POST["paydate1"] )&& !empty($_POST["paydate2"])){
          if ($paydate > $paydate2) {
              $test = false;
              $paydateErr="Invalid date range"; 
          } else $filter .=" AND (p.Pay_Date BETWEEN '$paydate' AND '$paydate2')";
      }

      if(!empty($_POST["salary1"])){
          if (!preg_match("/^\d+(\.\d{1,2})?$/", $_POST["salary1"])) {
            $salaryErr = "Invalid Salary format";
            $test = false;
          } else $salary1 = test_input($_POST["salary1"]);
      }
      if(!empty($_POST["salary2"])){
          if (!preg_match("/^\d+(\.\d{1,2})?$/", $_POST["salary2"])) {
            $salaryErr = "Invalid Salary format";
            $test = false;
          } else $salary2 = test_input($_POST["salary2"]);
      }

    if(!empty($_POST["salary1"] ) && empty($_POST["salary2"])){
        $filter .= " AND (e.Salary >= '$salary1')";
      } else if(empty($_POST["salary1"] ) && !empty($_POST["salary2"])){
        $filter .= " AND (e.Salary <= '$salary2')";
      } else if(!empty($_POST["salary1"] ) && !empty($_POST["salary2"])){
        if ($salary1 > $salary2) {
            $test = false;
            $salaryErr="Invalid salary range"; 
        }
        else $filter .= " AND (e.Salary BETWEEN '$salary1' AND '$salary2')";
      }
      if(!empty($_POST["division"])){
          $division = test_input($_POST["division"]);
          $filter .= " AND (ed.div_ID = '$division')";
      }
      if(!empty($_POST["jobtitle"])){
          $jobtitle = test_input($_POST["jobtitle"]);
          $filter .= " AND (ejt.job_title_id = '$jobtitle')";
      }
  }
  
  
  if($test && $report=="1"){
      $sql = "SELECT e.empid AS EmpID, 
                   p.earnings AS Earnings, 
                   p.fed_tax AS Fed_Tax, 
                   p.fed_med AS Medicare,
                   p.fed_ss AS Social_Security, 
                   p.state_tax AS State_Tax, 
                   p.retire_401k AS 401k, 
                   p.health_care AS Health_Care, 
                   p.pay_date AS Pay_Date
            FROM employees e
            LEFT JOIN payroll p ON e.empid = p.empid
            LEFT JOIN employee_division ed ON e.empid = ed.empid
            LEFT JOIN employee_job_titles ejt ON e.empid = ejt.empid
            $filter
            ";
            $_POST['sql'] = $sql;
  }else {
      $sql = $report;
  }
  
  
}
// Function to display report
function report($sql){
  $conn = getConnection();
  global $reporttype;
  if ($sql == "3") {
    $reporttype = "Job Title Report";
  } else if ($sql == "2") {
    $reporttype = "Division Report";
  } else {
    $reporttype = "Report";
  }
 
  if(!empty($sql)){
    echo "<h1>$reporttype</h1>
        <div class=\"table-wrapper\">
            <table id=\"employee-table\">"
            ;
  }
  if($sql=="3"){
    $row= isset($_GET['sort_column']) ? $_GET['sort_column'] : 'Job_Title';
    $order= isset($_GET['sort_order']) ?$_GET['sort_order'] : 'ASC';
    $_SESSION['sql'] = "3";

    echo "
        <thead id=\"employee-table-header\"> 
          <tr>
            <th data-column=\"Job_Title\">Job Title</th>
            <th data-column=\"January\">January</th>
            <th data-column=\"February\">February</th>
            <th data-column=\"March\">March</th>
            <th data-column=\"April\">April</th>
            <th data-column=\"May\">May</th>
            <th data-column=\"June\">June</th>
            <th data-column=\"July\">July</th>
            <th data-column=\"August\">August</th>
            <th data-column=\"September\">September</th>
            <th data-column=\"October\">October</th>
            <th data-column=\"November\">November</th>
            <th data-column=\"December\">December</th>
            <th data-column=\"YTD\">YTD</th>
          </tr>
        </thead>
        <tbody>
      ";

      $sql = "SELECT 
                  jt.job_title AS Job_Title,
                  SUM(CASE WHEN MONTH(p.pay_date) = 1 THEN p.earnings ELSE 0 END) AS January,
                  SUM(CASE WHEN MONTH(p.pay_date) = 2 THEN p.earnings ELSE 0 END) AS February,
                  SUM(CASE WHEN MONTH(p.pay_date) = 3 THEN p.earnings ELSE 0 END) AS March,
                  SUM(CASE WHEN MONTH(p.pay_date) = 4 THEN p.earnings ELSE 0 END) AS April,
                  SUM(CASE WHEN MONTH(p.pay_date) = 5 THEN p.earnings ELSE 0 END) AS May,
                  SUM(CASE WHEN MONTH(p.pay_date) = 6 THEN p.earnings ELSE 0 END) AS June,
                  SUM(CASE WHEN MONTH(p.pay_date) = 7 THEN p.earnings ELSE 0 END) AS July,
                  SUM(CASE WHEN MONTH(p.pay_date) = 8 THEN p.earnings ELSE 0 END) AS August,
                  SUM(CASE WHEN MONTH(p.pay_date) = 9 THEN p.earnings ELSE 0 END) AS September,
                  SUM(CASE WHEN MONTH(p.pay_date) = 10 THEN p.earnings ELSE 0 END) AS October,
                  SUM(CASE WHEN MONTH(p.pay_date) = 11 THEN p.earnings ELSE 0 END) AS November,
                  SUM(CASE WHEN MONTH(p.pay_date) = 12 THEN p.earnings ELSE 0 END) AS December,
                  SUM(p.earnings) AS YTD
              FROM payroll p
              JOIN employees e ON p.empid = e.empid
              JOIN employee_job_titles ejt ON e.empid = ejt.empid
              JOIN job_titles jt ON ejt.job_title_id = jt.job_title_id
              WHERE YEAR(p.pay_date) = 2025
              GROUP BY jt.job_title
      ";

      $sql .= " ORDER BY $row $order";
      $result = $conn->query($sql);

      $january = $february = $march = $april = $may = $june = $july = $august = $september = $october = $november = $december = $totalpay = 0;

      if ($result->num_rows > 0) {
          while ($row = $result->fetch_assoc()) {
              echo "
                    <tr>
                        <td>{$row['Job_Title']}</td>
                        <td>{$row['January']}</td>
                        <td>{$row['February']}</td>
                        <td>{$row['March']}</td>
                        <td>{$row['April']}</td>
                        <td>{$row['May']}</td>
                        <td>{$row['June']}</td>
                        <td>{$row['July']}</td>
                        <td>{$row['August']}</td>
                        <td>{$row['September']}</td>
                        <td>{$row['October']}</td>
                        <td>{$row['November']}</td>
                        <td>{$row['December']}</td>
                        <td>{$row['YTD']}</td>
                    </tr>
                ";
                $january += $row['January'];
                $february += $row['February'];
                $march += $row['March'];
                $april += $row['April'];
                $may += $row['May'];
                $june += $row['June'];
                $july += $row['July'];
                $august += $row['August'];
                $september += $row['September'];
                $october += $row['October'];
                $november += $row['November'];
                $december += $row['December'];
                $totalpay += $row['YTD'];
            }
        } else {
            echo "<tr><td colspan='14'>No Records found</td></tr>";
        }

        echo "
            <tr style='border-top: 1px solid black; font-weight:bold;'>
                <td>Total</td>
                <td>{$january}</td>
                <td>{$february}</td>
                <td>{$march}</td>
                <td>{$april}</td>
                <td>{$may}</td>
                <td>{$june}</td>
                <td>{$july}</td>
                <td>{$august}</td>
                <td>{$september}</td>
                <td>{$october}</td>
                <td>{$november}</td>
                <td>{$december}</td>
                <td>{$totalpay}</td>
            </tr>
        </tbody>
        ";

    
  }else if($sql=="2"){
    $row= isset($_GET['sort_column']) ? $_GET['sort_column'] : 'Division';
    $order= isset($_GET['sort_order']) ?$_GET['sort_order'] : 'ASC';
    $_SESSION['sql'] = "2";
    echo "
          <thead id=\"employee-table-header\"> 
            <tr>
              <th data-column=\"Division\">Division</th>
              <th data-column=\"January\">January</th>
              <th data-column=\"February\">February</th>
              <th data-column=\"March\">March</th>
              <th data-column=\"April\">April</th>
              <th data-column=\"May\">May</th>
              <th data-column=\"June\">June</th>
              <th data-column=\"July\">July</th>
              <th data-column=\"August\">August</th>
              <th data-column=\"September\">September</th>
              <th data-column=\"October\">October</th>
              <th data-column=\"November\">November</th>
              <th data-column=\"December\">December</th>
              <th data-column=\"YTD\">YTD</th>
            </tr>
          </thead>
          <tbody>
        ";

    $sql="SELECT 
                d.Name AS Division,
                SUM(CASE WHEN MONTH(p.pay_date) = 1 THEN p.earnings ELSE 0 END) AS January,
                SUM(CASE WHEN MONTH(p.pay_date) = 2 THEN p.earnings ELSE 0 END) AS February,
                SUM(CASE WHEN MONTH(p.pay_date) = 3 THEN p.earnings ELSE 0 END) AS March,
                SUM(CASE WHEN MONTH(p.pay_date) = 4 THEN p.earnings ELSE 0 END) AS April,
                SUM(CASE WHEN MONTH(p.pay_date) = 5 THEN p.earnings ELSE 0 END) AS May,
                SUM(CASE WHEN MONTH(p.pay_date) = 6 THEN p.earnings ELSE 0 END) AS June,
                SUM(CASE WHEN MONTH(p.pay_date) = 7 THEN p.earnings ELSE 0 END) AS July,
                SUM(CASE WHEN MONTH(p.pay_date) = 8 THEN p.earnings ELSE 0 END) AS August,
                SUM(CASE WHEN MONTH(p.pay_date) = 9 THEN p.earnings ELSE 0 END) AS September,
                SUM(CASE WHEN MONTH(p.pay_date) = 10 THEN p.earnings ELSE 0 END) AS October,
                SUM(CASE WHEN MONTH(p.pay_date) = 11 THEN p.earnings ELSE 0 END) AS November,
                SUM(CASE WHEN MONTH(p.pay_date) = 12 THEN p.earnings ELSE 0 END) AS December,
                SUM(p.earnings) AS YTD
            FROM payroll p
            JOIN employees e ON p.empid = e.empid
            JOIN employee_division ed ON e.empid = ed.empid
            JOIN division d ON ed.div_ID = d.ID
            WHERE YEAR(p.pay_date) = 2025
            GROUP BY d.Name
           ";
    
    $sql .= " ORDER BY $row $order";
    $result = $conn->query($sql);
    $january=$february=$march=$april=$may=$june=$july=$august=$september=$october=$november=$december=$totalpay=0;
    if ($result->num_rows > 0) {
      while ($row = $result->fetch_assoc()) {
          echo "
              <tr>
                  <td>{$row['Division']}</td>
                  <td>{$row['January']}</td>
                  <td>{$row['February']}</td>
                  <td>{$row['March']}</td>
                  <td>{$row['April']}</td>
                  <td>{$row['May']}</td>
                  <td>{$row['June']}</td>
                  <td>{$row['July']}</td>
                  <td>{$row['August']}</td>
                  <td>{$row['September']}</td>
                  <td>{$row['October']}</td>
                  <td>{$row['November']}</td>
                  <td>{$row['December']}</td>
                  <td>{$row['YTD']}</td>
              </tr>
          ";
          $january += $row['January'];
          $february += $row['February'];
          $march += $row['March'];
          $april += $row['April'];
          $may += $row['May'];
          $june += $row['June'];
          $july += $row['July'];
          $august += $row['August'];
          $september += $row['September'];
          $october += $row['October'];
          $november += $row['November'];
          $december += $row['December'];
          $totalpay += $row['YTD'];
      }
    } else {
          echo "<tr><td colspan='2'>No Records found</td></tr>";
      }
      echo "
                    <tr style='border-top: 1px solid black;'>
                        <td>Total</td>
                        <td>{$january}</td>
                        <td>{$february}</td>
                        <td>{$march}</td>
                        <td>{$april}</td>
                        <td>{$may}</td>
                        <td>{$june}</td>
                        <td>{$july}</td>
                        <td>{$august}</td>
                        <td>{$september}</td>
                        <td>{$october}</td>
                        <td>{$november}</td>
                        <td>{$december}</td>
                        <td>{$totalpay}</td>
                    </tr>
            </tbody>";
  }else if(empty($sql)){  
  }else{
    echo "
          <thead id=\"employee-table-header\"> 
                  <tr>
                    <th data-column=\"EmpID\">ID</th>
                    <th data-column=\"pay_date\">Pay Date</th>
                    <th data-column=\"earnings\">Earnings</th>
                    <th data-column=\"fed_tax\">Fed Tax</th>
                    <th data-column=\"fed_med\">Medicare</th>
                    <th data-column=\"fed_SS\">Social Security</th>
                    <th data-column=\"state_tax\">State Tax</th>
                    <th data-column=\"retire_401k\">401K</th>
                    <th data-column=\"health_care\">Health Care</th>
                </tr>
                </thead>
                    <tbody>
    ";
    $row= isset($_GET['sort_column']) ? $_GET['sort_column'] : 'EmpID';
    $order= isset($_GET['sort_order']) ?$_GET['sort_order'] : 'ASC';
    $_SESSION['sql'] = $sql;
    $sql .= " ORDER BY $row $order";
    $pay=$fedtax=$medicare=$ss=$state=$retire=$health=$paydate=0;
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            $pay += $row['Earnings'];
            $fedtax += $row['Fed_Tax'];  
            $medicare += $row['Medicare'];
            $ss += $row['Social_Security'];
            $state += $row['State_Tax'];
            $retire += $row['401k'];
            $health += $row['Health_Care'];

            echo "
                      <tr>
                      <td>{$row['EmpID']}</td>
                      <td>{$row['Pay_Date']}</td>
                      <td>{$row['Earnings']}</td>
                      <td>{$row['Fed_Tax']}</td>
                      <td>{$row['Medicare']}</td>
                      <td>{$row['Social_Security']}</td>
                      <td>{$row['Health_Care']}</td>
                      <td>{$row['State_Tax']}</td>
                      <td>{$row['401k']}</td>
                      </tr> 
                    
                    ";
        }
      } else {
          echo "<tr><td colspan='9'>No Records found</td></tr>";
      }
      // Display the total earnings and deductions
      echo "
                  <tr style='border-top: 1px solid black;'>
                      <td colspan='2'>Total</td>

                      <td>{$pay}</td>
                      <td>{$fedtax}</td>
                      <td>{$medicare}</td>
                      <td>{$ss}</td>
                      <td>{$health}</td>
                      <td>{$state}</td>
                      <td>{$retire}</td>
                  </tr>
                  </tbody>
      ";
    
  }
  
  
}
// Function to increase salary
function increasesalary(){
  $conn = getConnection();
  global $salary1, $salary2, $rate, $rateErr, $salaryErr;
  $test=true;
  $filter="WHERE";
  if(empty($_POST["salary1"]) && empty($_POST["salary2"])){
    $salaryErr = "Salary is required";
    $test = false;
  }
  if(!empty($_POST["salary1"])){
    if (!preg_match("/^\d+(\.\d{1,2})?$/", $_POST["salary1"])) {
      $salaryErr = "Invalid Salary format";
      $test = false;
    } else $salary1 = test_input($_POST["salary1"]);
    }
  if(!empty($_POST["salary2"])){
      if (!preg_match("/^\d+(\.\d{1,2})?$/", $_POST["salary2"])) {
        $salaryErr = "Invalid Salary format";
        $test = false;
      } else $salary2 = test_input($_POST["salary2"]);
  }
  if(!empty($_POST["salary1"] ) && empty($_POST["salary2"])){
    $filter .= " (Salary >= '$salary1')";
  } else if(empty($_POST["salary1"] ) && !empty($_POST["salary2"])){
    $filter .= " (Salary <= '$salary2')";
  } else if(!empty($_POST["salary1"] ) && !empty($_POST["salary2"])){
    if ($salary1 > $salary2) {
        $test = false;
        $salaryErr="Invalid salary range"; 
    }
    else $filter .= " (Salary BETWEEN '$salary1' AND '$salary2')";
  }
  if(empty($_POST["rate"])){
    $rateErr = "Rate is required";
    $test = false;
  }else if(!empty($_POST["rate"])){
    if(!preg_match("/^\d+(\.\d{1,2})?%$/", $_POST["rate"])) {
      $rateErr = "Invalid rate format";
      $test = false;
  } else $rate= test_input($_POST["rate"]);
  
  }
  if($test){
    $rate = rtrim($rate, '%');
    $rate = floatval($rate) / 100;
    $sql = "UPDATE employees
            SET Salary = Salary * (1 + $rate)
            $filter";
    if($conn->query($sql) === TRUE) {
      echo "<script>
              console.log('SQL Script: ' + " . json_encode($sql) . ");
              console.log('Rate: ' + " . json_encode($rate) . ");
              console.log('Salary Range: ' + " . json_encode($salary1 . " - " . $salary2) . ");
              alert('Salary updated successfully!');
              window.location.href = '../admin.php';
            </script>";
    } else {
      $rate=floatval($rate) * 100;
      $rate = number_format($rate, 2) . '%';
      echo "<script>
              alert('Error updating salary: " . $conn->error . "');
              window.history.back();
            </script>";
    }
  }
  $conn->close();
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (isset($_POST['addemployee'])) {
    addemployee();
  } else if (isset($_POST['updateemployee'])) {
    updateemployee();
  } else if (isset($_POST['terminateemployee'])) {
    terminateemployee($_SESSION['employeeid']);
  } else if (isset($_POST['logout'])) {
    logout();
  } else if (isset($_POST['updatedetails'])) {
    updatedetails();
  } else if (isset($_POST['updatepassword'])) {
    updatepassword();
  } 
  
}    

