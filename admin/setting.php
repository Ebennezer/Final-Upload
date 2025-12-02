<?php
session_start();
if ($_SESSION['role'] !== 'admin') {
    header('Location: ../index.php');
    exit();
}
$setting = true;
include 'backend/actions.php';
$info  = fillinfo();               // <-- IMPORTANT: capture return array
$name  = $info['full_name'] ?? '';
$email = $info['email'] ?? '';
$phone = $info['phone'] ?? '';
$dept  = $info['department_id'] ?? 0;

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Settings — ABC Corporation</title>
  <link rel="stylesheet" href="../css/styles.css" />
  <script src="../js/employee.js?v=3" defer></script>

</head>
<body>
    <div class="dashboard-container">
        <?php
        include 'sidebar.php';
        ?>
        <!-- Main Content -->
        <main class="main-content">
            <!-- Top Header -->
            <?php 
                include 'header.php'
            ;?>

            <!-- Dashboard Content -->
            <div class="dashboard-content">
                <div class="content-grid">
                    
                    
                    <main class="main">
                    

                    <section class="content container">
                        <div class="card">
                        <div class="card-header">
                            <div class="card-title">Profile</div>
                        </div>
                        <div class="card-body">
                          <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">  
                            <div class="form-grid cols-2">
                                <div class="field">
                                    <label class="label">Full Name</label>
                                    <input class="input" placeholder="John Anderson" value="<?php echo $name; ?>" Disabled/>
                                </div>
                                <?php if(isset($emailErr)) echo '<label class="form_error" style="color: red";>'.$emailErr.'</label>'; ?>
                                <div class="field">
                                    <label class="label">Email</label>
                                    <input class="input" type="email" placeholder="john.anderson@abc.com" name="email" value="<?php echo htmlspecialchars($email); ?>"/>
                                </div>
                                <div class="field">
                                    <label class="label">Department</label>
                                    <select class="select" name="department_id" Disabled>
                                    <option value= 0 <?php if($dept == 0) echo 'selected'; ?>>Select Department</option>
                                    <option value= 1 <?php if($dept == 1) echo 'selected'; ?>>Administration</option>
                                    <option value= 2 <?php if($dept == 2) echo 'selected'; ?>>Management</option>
                                    <option value= 3 <?php if($dept == 3) echo 'selected'; ?>>Front of House</option>
                                    <option value= 4 <?php if($dept == 4) echo 'selected'; ?>>Back of House</option>
                                    </select>
                                </div>
                                <?php if(isset($phoneErr)) echo '<label class="form_error" style="color: red";>'.$phoneErr.'</label>'; ?>
                                <div class="field">
                                    <label class="label">Phone</label>
                                    <input class="input" placeholder="+1 (555) 123-4567" name="phone" value="<?php echo htmlspecialchars($phone); ?>"/>
                                </div>
                            </div>
                            <div class="form-actions">
                                <button class="btn" type="submit" name="updatedetails" >Update Profile</button>
                                <button class="btn ghost" type="reset">Cancel</button>
                            </div>
                            </form>
                        </div>
                        </div>

                        <div style="height:16px"></div>

                        <div class="card">
                            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                                <div class="card-header"><div class="card-title">Security</div></div>
                                <div class="card-body">
                                    <div class="form-grid cols-2">
                                        <?php if(isset($oldpassErr)) echo '<label class="form_error" style="color: red";>'.$oldpassErr.'</label>'; ?>
                                        <div class="field">
                                            <label class="label">Current Password</label>
                                            <input class="input" type="password" name="oldpass" placeholder="Enter current password"/>
                                        </div>
                                        <?php if(isset($newpassErr)) echo '<label class="form_error" style="color: red";>'.$newpassErr.'</label>'; ?>
                                        <div class="field">
                                            <label class="label">New Password</label>
                                            <input class="input" type="password" name="newpass" placeholder="Enter new password"/>
                                        </div>
                                        <?php if(isset($confpassErr)) echo '<label class="form_error" style="color: red";>'.$confpassErr.'</label>'; ?>
                                        <div class="field">
                                            <label class="label">Confirm New Password</label>
                                            <input class="input" type="password" name="confpass" placeholder="Confirm new password"/>
                                        </div>
                                        <div class="field">
                                            <label class="label">Two-Factor Authentication</label>
                                            <select class="select">
                                            <option>Disabled</option>
                                            <option>Authenticator App</option>
                                            <option>SMS</option>
                                            </select>
                                        </div>
                                        <div class="field">
                                            <label class="label">Session Timeout (minutes)</label>
                                            <input class="input" type="number" value="30" />
                                        </div>
                                    </div>
                                    <div class="form-actions">
                                        <button class="btn" type="submit" name="updatepassword">Update Security</button>
                                        <button class="btn ghost">Cancel</button>
                                    </div>
                                </div>
                            </form>
                        </div>

                        <div style="height:16px"></div>

                    <div class="card">
                        
                        <div class="card-body">
                            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                                <button class="btn" style="color: red;" id="logout" name="logout">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:8px">
                                        <path d="M9 21H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3"/>
                                        <path d="M16 17l5-5-5-5"/>
                                        <path d="M21 12H9"/>
                                    </svg>
                                    Log out
                                </button>
                            </form>
                    </div>
                    </section>
                    </main>

                   

                 


                   
                   
                </div>
            </div>
        </main>
    </div>
 

</body>
</html>
