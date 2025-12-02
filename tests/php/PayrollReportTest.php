<?php
use PHPUnit\Framework\TestCase;
require __DIR__.'/bootstrap.php';

final class PayrollReportTest extends TestCase {
    public function test_admin_can_get_aggregated_totals_and_exports(): void {
        $_SESSION = ['role'=>'Admin','user_id'=>1];
        $_GET = ['action'=>'payrollReport','month'=>'2025-09','group_by'=>'title']; $_POST=[];
        $_REQUEST = array_merge($_GET, $_POST);

        $GLOBALS['db'] = new FakePDO([
            'payrollAgg' => [
                ['title'=>'SWE','total'=>195000,'count'=>2],
                ['title'=>'HRBP','total'=> 70000,'count'=>1],
            ]
        ]);

        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); $out = ob_get_clean();
        $json = json_decode($out, true);

        $this->assertSame(200, http_response_code());
        $this->assertEquals(195000, $json['totals']['SWE']);
        $this->assertEquals(70000,  $json['totals']['HRBP']);
        $this->assertSame(3, array_sum($json['counts']));

        // CSV export
        $_GET = ['action'=>'exportPayroll','format'=>'csv','month'=>'2025-09','group_by'=>'title']; $_POST=[]; $_REQUEST = array_merge($_GET, $_POST);
        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); $csv = ob_get_clean();
        $this->assertStringContainsString('SWE,195000', $csv);

        // PDF/meta export (fake JSON meta)
        $_GET = ['action'=>'exportPayroll','format'=>'pdf','month'=>'2025-09','group_by'=>'title']; $_POST=[]; $_REQUEST = array_merge($_GET, $_POST);
        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); $pdfMeta = ob_get_clean();
        $this->assertStringContainsString('"total_all":265000', $pdfMeta);
    }

    public function test_employee_forbidden_on_payroll_reports(): void {
        $_SESSION = ['role'=>'Employee','user_id'=>22];
        $_GET = ['action'=>'payrollReport','month'=>'2025-09','group_by'=>'title']; $_POST=[]; $_REQUEST = array_merge($_GET, $_POST);

        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); ob_end_clean();
        $this->assertSame(403, http_response_code());
    }
}
?>