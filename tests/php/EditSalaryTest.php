<?php
use PHPUnit\Framework\TestCase;
require __DIR__.'/bootstrap.php';

final class EditSalaryTest extends TestCase {
    public function test_negative_salary_validation_blocks_save(): void {
        $_SESSION = ['role'=>'Admin','user_id'=>1];
        $_POST = ['action'=>'updateSalary','employee_id'=>1,'salary'=>-1];
        $_GET = []; $_REQUEST = array_merge($_GET, $_POST);
        $GLOBALS['db'] = new FakePDO();

        ob_start();
        include __DIR__ . '/../../admin/backend/actions.php';
        run_actions();
        $out = ob_get_clean();
        $json = json_decode($out, true);

        $this->assertSame(422, http_response_code(), 'Should be Unprocessable Entity');
        $this->assertSame('SALARY_INVALID', $json['error_code'] ?? null);
    }

    public function test_valid_salary_persists_and_audits(): void {
        $_SESSION = ['role'=>'Admin','user_id'=>7];
        $_POST = ['action'=>'updateSalary','employee_id'=>1,'salary'=>82000];
        $_GET = []; $_REQUEST = array_merge($_GET, $_POST);
        $GLOBALS['db'] = new FakePDO();

        ob_start();
        include __DIR__ . '/../../admin/backend/actions.php';
        run_actions();
        $out = ob_get_clean();
        $json = json_decode($out, true);

        $this->assertSame(200, http_response_code());
        $this->assertSame(82000, $json['employee']['salary'] ?? null);
        $this->assertSame('UPDATE_SALARY', $json['audit']['event'] ?? null);
        $this->assertSame(7, $json['audit']['actor_id'] ?? null);
        $this->assertSame(80000, $json['audit']['old'] ?? 80000);
        $this->assertSame(82000, $json['audit']['new'] ?? null);
    }
}
?>