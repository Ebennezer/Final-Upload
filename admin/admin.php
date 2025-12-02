<?php
    session_start();
    if ($_SESSION['role'] !== 'admin') {
        header('Location: ../index.php');
        exit();
    }
    $admin = true; 
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="../css/styles.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;550;600&display=swap" rel="stylesheet">
</head>
<body>
    <div class="dashboard-container">
        <!-- Sidebar -->
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
                    <!-- Messages Section -->
                    <section class="messages-section">
                        <div class="card">
                            <div class="card-header">
                                <h3>Recent Messages</h3>
                                <a href="#" class="view-all-link">View All</a>
                            </div>
                            <div class="messages-table">
                                <div class="table-header">
                                    <div class="table-cell">From</div>
                                    <div class="table-cell">Subject / Title</div>
                                    <div class="table-cell">Date</div>
                                </div>
                                <div class="table-body" id="messagesTable">
                                    <!-- Messages will be populated by JavaScript -->
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Weekly Statistics -->
                    <section class="stats-section">
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-icon stat-icon--blue">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="12" cy="12" r="10"/>
                                        <polyline points="12,6 12,12 16,14"/>
                                    </svg>
                                </div>
                                <div class="stat-content">
                                    <div class="stat-number" id="hoursWorked">38.5</div>
                                    <div class="stat-label">Hours Worked</div>
                                </div>
                            </div>

                            <div class="stat-card">
                                <div class="stat-icon stat-icon--purple">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="9,11 12,14 22,4"/>
                                        <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
                                    </svg>
                                </div>
                                <div class="stat-content">
                                    <div class="stat-number" id="tasksCompleted">24</div>
                                    <div class="stat-label">Tasks Completed</div>
                                </div>
                            </div>

                            <div class="stat-card">
                                <div class="stat-icon stat-icon--yellow">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                                        <circle cx="9" cy="7" r="4"/>
                                        <path d="M23 21v-2a4 4 0 00-3-3.87"/>
                                        <path d="M16 3.13a4 4 0 010 7.75"/>
                                    </svg>
                                </div>
                                <div class="stat-content">
                                    <div class="stat-number" id="meetings">12</div>
                                    <div class="stat-label">Meetings</div>
                                </div>
                            </div>

                            <div class="stat-card">
                                <div class="stat-icon stat-icon--teal">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
                                        <line x1="16" y1="2" x2="16" y2="6"/>
                                        <line x1="8" y1="2" x2="8" y2="6"/>
                                        <line x1="3" y1="10" x2="21" y2="10"/>
                                    </svg>
                                </div>
                                <div class="stat-content">
                                    <div class="stat-number" id="events">8</div>
                                    <div class="stat-label">Events</div>
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Calendar Widget -->
                    

                    <!-- Tasks/Appointments Table -->
                    <section class="tasks-section">
                        <div class="card">
                            <div class="card-header">
                                <h3>My Tasks & Appointments</h3>
                                <a href="#" class="view-all-link">View All</a>
                            </div>
                            <div class="tasks-table">
                                <div class="table-header">
                                    <div class="table-cell">Task / Employee</div>
                                    <div class="table-cell">Date & Time</div>
                                    <div class="table-cell">Status</div>
                                </div>
                                <div class="table-body" id="tasksTable">
                                    <!-- Tasks will be populated by JavaScript -->
                                </div>
                            </div>
                        </div>
                    </section>

                    <!-- Bottom Statistics -->
                    <section class="bottom-stats-section">
                        <div class="bottom-stats-grid">
                            <div class="card earnings-card">
                                <div class="card-header">
                                    <h3>Monthly Profit</h3>
                                </div>
                                <div class="earnings-content">
                                    <div class="earnings-amount">$8,750</div>
                                    <div class="earnings-change positive">+12.5%</div>
                                </div>
                            </div>

                            <div class="card performance-card">
                                <div class="card-header">
                                    <h3>Team Performance</h3>
                                </div>
                                <div class="performance-content">
                                    <div class="performance-score">92</div>
                                    <div class="performance-trend">
                                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                            <polyline points="23,6 13.5,15.5 8.5,10.5 1,18"/>
                                            <polyline points="17,6 23,6 23,12"/>
                                        </svg>
                                        <span>+5 from last month</span>
                                    </div>
                                </div>
                            </div>

                           
                        </div>
                    </section>
                </div>
            </div>
        </main>
    </div>

    <script src="app.js"></script>
</body>
</html>