<?php
session_start();
if ($_SESSION['role'] !== 'admin') {
    header('Location: ../index.php');
    exit();
}
$payroll = true;
include 'backend/actions.php';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Payroll — ABC Corporation</title>
  <link rel="stylesheet" href="../css/styles.css" />
    <script src="../js/employee.js" defer></script>
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
                    <header class="topbar">
                        
                        

                    <section class="content container">
            
                    </header>
                        <div class="payroll-summary">
                            <div class="payroll-card">
                                <div class="text-muted">Total Gross</div>
                                <div style="font-weight:800;font-size:22px">
                                    <span id="payrollTotalGross">
                                        $<?php echo number_format($totalGross ?? 0, 2); ?>
                                    </span></div>
                            </div>
                            <div class="payroll-card">
                                <div class="text-muted">Pending</div>
                                <div style="font-weight:800;font-size:22px">
                                     <span id="payrollCount">
                                        <?php echo $totalRecords ?? 0; ?>
                                    </span>
                                </div>
                            </div>
                            <div class="payroll-card">
                                <div class="text-muted">This Month</div>
                                <div style="font-weight:800;font-size:22px">
                                    <span id="payrollTotalNet">
                                        $<?php echo number_format($totalNet ?? 0, 2); ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                        <div style="height:12px"></div>
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title"><h3>Payroll</h3></div>
                                <div class="search-bar">
                                      <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                          <circle cx="11" cy="11" r="8"/>
                                          <path d="M21 21l-4.35-4.35"/>
                                      </svg>
                                      <input type="text" placeholder="Search employees, departments, or tasks..." class="search-input" id="employeeSearch">
                                </div>
                                <div style="display:flex;gap:8px;align-items:center">
                                    <select class="select" id="departmentFilter" style="min-width:140px">
                                        <option value="">All Departments</option>
                                        <option value="Administration">Administration</option>
                                        <option value="Management">Management</option>
                                        <option value="Front of House">FOH</option>
                                        <option value="Back of House">BOH</option>
                                    </select>
                                    <select class="select" id="departmentFilter" style="min-width:140px">
                                        <option value="">All Departments</option>
                                        <option value="Administration">Administration</option>
                                        <option value="Management">Management</option>
                                        <option value="Front of House">FOH</option>
                                        <option value="Back of House">BOH</option>
                                    </select>
                                </div>
                            </div>
                            <div class="card-body" >
                                <div class="payroll-table">
                                    <table id="payrollTable">
                                        <thead>
                                            <tr>
                                                <th data-column="EmpID" >ID</th>
                                                <th data-column="First_Name">First Name </th>
                                                <th data-column="Last_Name">Last Name </th>
                                                <th data-column="job_title">Job Title</th>
                                                <th data-column="division">Division</th>
                                                <th data-column="period">Period</th>
                                                <th data-column="gross">Gross Pay</th>
                                                <th data-column="taxes">Taxes</th>
                                                <th data-column="deductions">Deductions</th>
                                                <th data-column="net">Net Pay</th>
                                                <th data-column="issued">Issued</th>
                                                <th data-column="notes">Notes</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                            viewpayroll(); 
                                            ?>
                                        </tbody>
                                    </table>
                                </div>

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
