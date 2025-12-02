<?php
session_start();

// allow either location depending on where you place this file
$actions1 = __DIR__ . '/admin/backend/actions.php';
$actions2 = __DIR__ . '/admin/actions.php';

if (file_exists($actions1)) require $actions1;
else require $actions2;

$uid   = $_GET['uid'] ?? '';
$token = $_GET['token'] ?? '';

[$ok, $msg] = verifyEmailFromLink($uid, $token);

// Simple screen + redirect
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Email Verification</title>
</head>
<body style="font-family: Arial; padding: 24px;">
<script>
    alert(<?php echo json_encode(($ok ? "✅ Verified: " : "❌ Not Verified: ") . $msg); ?>);
    window.location.href = <?php echo json_encode(rtrim(APP_BASE_URL, '/').'/index.php'); ?>;
</script>
</body>
</html>
