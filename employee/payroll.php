<?php
session_start();
if ($_SESSION['role'] !== 'employee') {
    header('Location: ../index.php');
    exit();
}
$payroll = true;
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Payroll — ABC Corporation</title>
  <link rel="stylesheet" href="../css/styles.css" />
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
                    
                        <div class="payroll-summary">
                            <div class="payroll-card">
                                <div class="text-muted">Total Earnings</div>
                                <div style="font-weight:800;font-size:22px">$132,450</div>
                            </div>
                            <div class="payroll-card">
                                <div class="text-muted">Pending</div>
                                <div style="font-weight:800;font-size:22px">$18,200</div>
                            </div>
                            <div class="payroll-card">
                                <div class="text-muted">This Month</div>
                                <div style="font-weight:800;font-size:22px">$150,650</div>
                            </div>
                        </div>
                        <div style="height:12px"></div>
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">Actions</div>
                            </div>
                            <div class="card-body" style="display:flex;gap:10px;flex-wrap:wrap">
                                <button class="btn">Run Payroll</button>
                                <button class="btn ghost">Export CSV</button>
                                <button class="btn ghost">View Reports</button>
                            </div>
                        </div>
                    </section>
                    </main>

                   

                 


                   
                   
                </div>
            </div>
        </main>
    </div>
  

  <script>
    document.getElementById('menuToggle')?.addEventListener('click',()=>document.getElementById('sidebar').classList.toggle('open'));
  </script>
</body>
</html>
