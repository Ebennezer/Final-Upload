<?php
use PHPUnit\Framework\TestCase;
require __DIR__.'/bootstrap.php';

final class MassSalaryUpdateTest extends TestCase {
    public function test_preview_and_apply_percentage_increase(): void {
        $_SESSION = ['role'=>'Admin','user_id'=>9];
        $employees = [
            ['id'=>10,'title'=>'SWE','division'=>'Engineering','salary'=>100000],
            ['id'=>11,'title'=>'SWE','division'=>'Engineering','salary'=> 90000],
            ['id'=>12,'title'=>'HRBP','division'=>'HR','salary'=> 70000],
        ];
        $GLOBALS['db'] = new FakePDO(['employees'=>$employees]);

        // Preview (3% Engineering only)
        $_GET = ['action'=>'massSalaryPreview','division'=>'Engineering','method'=>'percentage','value'=>3];
        $_POST = []; $_REQUEST = array_merge($_GET, $_POST);
        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); $preview = json_decode(ob_get_clean(), true);

        $this->assertSame(200, http_response_code());
        $this->assertCount(2, $preview['rows']);
        $this->assertSame(103000, $preview['rows'][0]['new_salary']);
        $this->assertSame( 92700, $preview['rows'][1]['new_salary']);
        $this->assertSame(3000, $preview['rows'][0]['delta']);
        $this->assertSame(2700, $preview['rows'][1]['delta']);

        // Apply
        $_POST = ['action'=>'massSalaryApply','division'=>'Engineering','method'=>'percentage','value'=>3];
        $_GET = []; $_REQUEST = array_merge($_GET, $_POST);
        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); $apply = json_decode(ob_get_clean(), true);

        $this->assertSame(200, http_response_code());
        $this->assertSame(2, $apply['updated_count']);

        // Read-back one updated employee
        $_GET = ['action'=>'getEmployee','id'=>10]; $_POST = []; $_REQUEST = array_merge($_GET, $_POST);
        ob_start(); include __DIR__.'/../../admin/backend/actions.php'; run_actions(); $emp = json_decode(ob_get_clean(), true);
        $this->assertSame(103000, $emp['salary'] ?? null);

        // Audits tagged
        $this->assertSame('MASS_UPDATE_SALARY', $apply['audit']['event'] ?? null);
        $this->assertSame(2, $apply['audit']['entries'] ?? null);
    }
}
?>