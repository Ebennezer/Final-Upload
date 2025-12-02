<?php
    session_start();
    if ($_SESSION['role'] !== 'admin') {
        header('Location: ../index.php');
        exit();
    }
    $employees = true;
    include 'backend/actions.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Employees — ABC Corporation</title>
  <script src="../js/employee.js" defer></script>
  <link rel="stylesheet" href="../css/styles.css" />
</head>
<body>
  <div class="dashboard-container">
    <!-- Sidebar -->
    <?php
        include 'sidebar.php';
    ?>

    <!-- Main -->
    <main class="main-content">
      <?php 
        include 'header.php'
        ;?>
    <div class="dashboard-content">
                <div class="content-grid">
                    <main class="main">  
                        <section class="content container">
                            <div class="card">
                              <div class="card-header">
                                <div class="card-title">Employee Directory</div>
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
                                </div>
                              </div>
                            <div class="card-body" >
                                <div class="employees-table">
                                    <table id="employeesTable">
                                        <thead id="employee-table-header">
                                         <tr>
                                            <th data-column="EmpID">ID</th>
                                            <th data-column="First_Name">First Name </th>
                                            <th data-column="Last_Name">Last Name </th>
                                            <th data-column="Gender">Gender </th>
                                            <th data-column="Birth_Date">Date of Birth </th>
                                            <th data-column="Phone">Phone </th>
                                            <th data-column="Email">Email </th>
                                            <th data-column="Job_Title">Job Title </th>
                                            <th data-column="Division">Division </th>
                                            <th data-column="Salary">Salary </th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          <?php
                                          viewemployees();
                                          ?>  
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            </div>

                            <!-- Pagination -->
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:16px">
                            <div class="text-muted">Showing <span id="employeeCount">0</span> employees</div>
                            <div style="display:flex;gap:8px">
                              <button id="exportEmployees" class="btn btn-sm btn-outline-success">Export</button>
                            </div>
                            </div>
                        </section>
      </main>
      </div>
      </div>
    </main>
  </div>
</body>
</html>