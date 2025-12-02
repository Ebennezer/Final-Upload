

//  NEW: CSV helper for Excel expor
function csvEscape(value) {
    if (value == null) return '';
    const v = String(value);
    if (/[",\n]/.test(v)) {
        return '"' + v.replace(/"/g, '""') + '"';
    }
    return v;
}
// Export visible employees to CSV
function exportEmployeesToCSV() {
    const table = document.getElementById('employeesTable');
    if (!table) return;

    const rows = [];

    // Header row
    const headerCells = table.querySelectorAll('thead th');
    const headerValues = Array.from(headerCells).map(th =>
        csvEscape(th.textContent.trim())
    );
    rows.push(headerValues.join(','));

    // Body rows – only visible rows (respect search + department filter)
    const bodyRows = table.querySelectorAll('tbody tr');
    bodyRows.forEach(tr => {
        if (tr.style.display === 'none') return;

        const cellValues = Array.from(tr.cells).map(td =>
            csvEscape(td.textContent.trim())
        );
        rows.push(cellValues.join(','));
    });

    const csvContent = rows.join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'employees.csv'); // Excel-friendly
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}
// Update employee count based on current filter
function updateEmployeeCount() {
    const tbody = document.querySelector('#employeesTable tbody');
    const el = document.getElementById('employeeCount');
    if (!tbody || !el) return;

    let visible = 0;
    tbody.querySelectorAll('tr').forEach(row => {
        // Count only rows that are not hidden by the filter
        if (row.style.display !== 'none') {
            visible++;
        }
    });

    if (visible === 0) {
        const tr = document.createElement('tr');
        tr.classList.add('no-results-row');

        const td = document.createElement('td');
        // Use actual column count if possible
        const table = tbody.closest('table');
        const colCount = table?.tHead?.rows[0].cells.length || 10;

        td.colSpan = colCount;
        td.textContent = 'No results found';
        td.style.textAlign = 'center';

        tr.appendChild(td);
        tbody.appendChild(tr);
    } else {
        // Remove any existing "No results" row
        const noResultsRow = tbody.querySelector('.no-results-row');
        if (noResultsRow) {
            noResultsRow.remove();
        }
    }
    
    el.textContent = visible;
}
// Apply both search and department filters
function applyEmployeeFilters() {
    const table = document.getElementById('employeesTable');
    if (!table) return;

    const tbody = table.querySelector('tbody');
    const rows  = tbody.querySelectorAll('tr');

    const searchInput = document.getElementById('employeeSearch');
    const deptSelect  = document.getElementById('departmentFilter');

    const query = (searchInput?.value || '').toLowerCase().trim(); // search text
    const dept  = (deptSelect?.value || '').toLowerCase().trim();  // department value

    rows.forEach(row => {
       
        const rowText = row.textContent.toLowerCase();
        const divisionCell = (row.cells[8]?.textContent || '').toLowerCase(); // adjust index if needed

        // true if search is empty OR row contains search text
        const matchesSearch = !query || rowText.includes(query);

        // true if dept is empty OR division cell matches department
        const matchesDept   = !dept || divisionCell.includes(dept);

        // Final condition: both must be true
        const visible = matchesSearch && matchesDept;

        row.style.display = visible ? '' : 'none';
    });

    // Update count + "No results" row
    updateEmployeeCount();
}

// Apply both search + month filters together
function applyPayrollFilters() {
    const table = document.getElementById('payrollTable');
    if (!table) return; // not on payroll page

    const tbody = table.querySelector('tbody');
    const rows  = tbody.querySelectorAll('tr');

    const searchInput = document.getElementById('payrollSearch');
    const monthInput  = document.getElementById('payrollMonthFilter');

    const query = (searchInput?.value || '').toLowerCase().trim(); // search text
    const month = (monthInput?.value || '').trim();                // "YYYY-MM"

    rows.forEach(row => {
        // ignore the special "no results" row
        if (row.classList.contains('no-results-row')) return;

        const rowText  = row.textContent.toLowerCase();
        const rowMonth = row.getAttribute('data-period') || '';

        // search condition: if search box empty, always true
        const matchesSearch = !query || rowText.includes(query);

        // month condition: if month input empty, always true
        const matchesMonth  = !month || rowMonth === month;

        const visible = matchesSearch && matchesMonth;

        row.style.display = visible ? '' : 'none';
    });

    updatePayrollSummary();
}

// Count visible rows + recompute totals + handle "no results"
function updatePayrollSummary() {
    const table = document.getElementById('payrollTable');
    const tbody = table?.querySelector('tbody');
    if (!table || !tbody) return;

    // remove old "no results" row if any
    const oldNoRow = tbody.querySelector('.no-results-row');
    if (oldNoRow) oldNoRow.remove();

    let visible    = 0;
    let totalGross = 0;
    let totalNet   = 0;

    tbody.querySelectorAll('tr').forEach(row => {
        if (row.classList.contains('no-results-row')) return;
        if (row.style.display === 'none') return;

        visible++;

        // adjust column indexes if your table differs:
        // 3 = Gross, 6 = Net (0-based: 0..8)
        const grossCell = row.cells[3];
        const netCell   = row.cells[6];

        if (grossCell) {
            const g = parseFloat(grossCell.textContent.replace(/[^0-9.\-]/g, ''));
            if (!isNaN(g)) totalGross += g;
        }
        if (netCell) {
            const n = parseFloat(netCell.textContent.replace(/[^0-9.\-]/g, ''));
            if (!isNaN(n)) totalNet += n;
        }
    });

    // If no visible rows, add "No results" message row
    if (visible === 0) {
        const tr = document.createElement('tr');
        tr.classList.add('no-results-row');

        const td = document.createElement('td');
        td.colSpan = table.tHead?.rows[0].cells.length || 10;
        td.textContent = 'No payroll records match your filters';
        td.style.textAlign = 'center';

        tr.appendChild(td);
        tbody.appendChild(tr);
    }

    // Update summary widgets (if present)
    const countEl = document.getElementById('payrollCount');
    if (countEl) countEl.textContent = visible;

    const grossEl = document.getElementById('payrollTotalGross');
    if (grossEl) grossEl.textContent = '$' + totalGross.toFixed(2);

    const netEl = document.getElementById('payrollTotalNet');
    if (netEl) netEl.textContent = '$' + totalNet.toFixed(2);
}

// Client-side column sorting (Employee Table)
document.addEventListener('DOMContentLoaded', () => {
    const table = document.getElementById('employeesTable');
    if (!table) return;

    // Only sort headers that have data-column (like your old code)
    const tableHeaders = table.querySelectorAll('thead th[data-column]');
    const tbody = table.querySelector('tbody');
    const trow = tbody.querySelector('tr');

    let currentColumnIndex = null;
    let currentOrder = 'asc'; // or 'desc'

    updateEmployeeCount();

    tableHeaders.forEach((header, index) => {
        header.style.cursor = 'pointer';

        header.addEventListener('click', () => {
            // Toggle order if clicking same column
            const isSameColumn = currentColumnIndex === index;
            const newOrder = (isSameColumn && currentOrder === 'asc') ? 'desc' : 'asc';

            currentColumnIndex = index;
            currentOrder = newOrder;

            // Get all rows as an array
            const rows = Array.from(tbody.querySelectorAll('tr'));

            rows.sort((rowA, rowB) => {
                const cellA = rowA.cells[index]?.textContent.trim() || '';
                const cellB = rowB.cells[index]?.textContent.trim() || '';

                // Try numeric compare first (for empid, salary, etc.)
                const numA = parseFloat(cellA.replace(/[^0-9.\-]/g, ''));
                const numB = parseFloat(cellB.replace(/[^0-9.\-]/g, ''));

                let cmp;
                if (!isNaN(numA) && !isNaN(numB)) {
                    cmp = numA - numB;
                } else {
                    cmp = cellA.localeCompare(cellB, undefined, { numeric: true, sensitivity: 'base' });
                }

                return currentOrder === 'asc' ? cmp : -cmp;
            });

            // Re-attach rows in new order
            rows.forEach(row => tbody.appendChild(row));
            updateEmployeeCount();
            
        });
    });
    // Enable clicking a table row to open employee details page
    tbody.querySelectorAll('tr').forEach(row => {
        if (row.classList.contains('no-results-row')) return;
        row.style.cursor = 'pointer';
        row.addEventListener('click', (e) => {
            // Don't navigate when interacting with buttons/links/inputs inside the row
            if (e.target.closest('button, a, input, label')) return;
            const id = row.cells[0]?.textContent.trim();
            if (!id) return;
            window.sessionStorage.setItem('empid', id);
            // Adjust path if your file is in a different folder
            const encodedId = btoa(String(id));  // base64 encode
            window.location.href = 'employeedetails.php?eid=' + encodeURIComponent(encodedId);

            //window.location.href = `employeedetails.php`;
            console.log('Navigating to employeedetails.php for empid:', id);
        });
    });
});
// Client-side column sorting (Payroll Table)
document.addEventListener('DOMContentLoaded', () => {
    const table = document.getElementById('payrollTable');
    if (!table) return; // not on payroll page

    const tableHeaders = table.querySelectorAll('thead th[data-column]');
    const tbody = table.querySelector('tbody');
    
    let currentColumnIndex = null;
    let currentOrder = 'asc';

    tableHeaders.forEach((header, index) => {
        header.style.cursor = 'pointer';

        header.addEventListener('click', () => {
            const isSameColumn = currentColumnIndex === index;
            const newOrder = (isSameColumn && currentOrder === 'asc') ? 'desc' : 'asc';

            currentColumnIndex = index;
            currentOrder = newOrder;

            const rows = Array.from(tbody.querySelectorAll('tr'));

            rows.sort((rowA, rowB) => {
                const cellA = (rowA.cells[index]?.textContent || '').trim();
                const cellB = (rowB.cells[index]?.textContent || '').trim();

                const numA = parseFloat(cellA.replace(/[^0-9.\-]/g, ''));
                const numB = parseFloat(cellB.replace(/[^0-9.\-]/g, ''));

                let cmp;
                if (!isNaN(numA) && !isNaN(numB)) {
                    cmp = numA - numB;
                } else {
                    cmp = cellA.localeCompare(cellB, undefined, { numeric: true, sensitivity: 'base' });
                }

                return currentOrder === 'asc' ? cmp : -cmp;
            });

            rows.forEach(row => tbody.appendChild(row));
        });
    });
   
});


// Sidebar toggle
document.getElementById('menuToggle')?.addEventListener('click', ()=>{
    document.getElementById('sidebar')?.classList.toggle('open');
});
// Logo click navigates to homepage
document.getElementById('companylogo')?.addEventListener('click', (e) => {
    e.preventDefault();
    window.location.href = '../index.php';
});
// Search functionality
document.getElementById('employeeSearch')?.addEventListener('input', (e)=>{
    const query = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('#employeesTable tbody tr');
    rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query) ? '' : 'none';
    });
});

// Employee Table filters
document.getElementById('employeeSearch')?.addEventListener('input', applyEmployeeFilters);
document.getElementById('departmentFilter')?.addEventListener('change', applyEmployeeFilters);

// Button actions
document.getElementById('addEmployee')?.addEventListener('click', ()=>{
    alert('Add Employee functionality');
});

// Export button triggers CSV/Excel download
document.getElementById('exportEmployees')?.addEventListener('click', ()=>{
    exportEmployeesToCSV();
});


document.addEventListener('DOMContentLoaded', function() {
    const calendarContainer = document.getElementById('calendarContainer');
    const currentMonthSpan = document.getElementById('currentMonth');
    const prevBtn = document.getElementById('prevMonth');
    const nextBtn = document.getElementById('nextMonth');
    const logoutBtn = document.getElementById('logoutBtn');
    const payrollSearch = document.getElementById('payrollSearch');
    const payrollMonth  = document.getElementById('payrollMonthFilter');

    let today = new Date();
    let currentMonth = today.getMonth();
    let currentYear = today.getFullYear();

    applyEmployeeFilters();
    

    if (payrollSearch) {
        payrollSearch.addEventListener('input', applyPayrollFilters);
    }

    if (payrollMonth) {
        payrollMonth.addEventListener('change', applyPayrollFilters);
    }

    // If we're on the payroll page, run once to sync the summary
    if (document.getElementById('payrollTable')) {
        applyPayrollFilters();
    }

    function renderCalendar(month, year) {
        const monthNames = [
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        ];
        currentMonthSpan.textContent = `${monthNames[month]} ${year}`;

        const firstDay = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();

        let table = '<table class="calendar-table">';
        table += '<thead><tr>';
        ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].forEach(day => {
            table += `<th>${day}</th>`;
        });
        table += '</tr></thead><tbody><tr>';

        let day = 1;
        // Fill initial empty cells
        for (let i = 0; i < firstDay; i++) {
            table += '<td></td>';
        }
        // Fill days
        for (let i = firstDay; i < 7; i++) {
            table += `<td>${day}</td>`;
            day++;
        }
        table += '</tr>';

        while (day <= daysInMonth) {
            table += '<tr>';
            for (let i = 0; i < 7; i++) {
                if (day > daysInMonth) {
                    table += '<td></td>';
                } else {
                    table += `<td>${day}</td>`;
                    day++;
                }
            }
            table += '</tr>';
        }
        table += '</tbody></table>';
        calendarContainer.innerHTML = table;
        console.log('Calendar rendered for', monthNames[month], year);
    }
    if (calendarContainer) {
    prevBtn.addEventListener('click', function() {
        currentMonth--;
        if (currentMonth < 0) {
            currentMonth = 11;
            currentYear--;
        }
        renderCalendar(currentMonth, currentYear);
    });

    nextBtn.addEventListener('click', function() {
        currentMonth++;
        if (currentMonth > 11) {
            currentMonth = 0;
            currentYear++;
        }
        renderCalendar(currentMonth, currentYear);
    });
    // Initial render
    renderCalendar(currentMonth, currentYear);
    }
    if (logoutBtn){
        logoutBtn.addEventListener('click', function (e) {
            e.preventDefault();
            logoutUser();
        });
    }

    
});

