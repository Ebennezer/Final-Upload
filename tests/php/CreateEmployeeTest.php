<?php
use PHPUnit\Framework\TestCase;
require __DIR__.'/bootstrap.php';

final class CreateEmployeeTest extends TestCase {
    public function test_admin_creates_employee_gets_201_and_audit_logged(): void {
        $_SESSION = ['role' => 'Admin', 'user_id' => 99];
        $_POST = [
            'action' => 'createEmployee',
            'first_name'=>'Iman','last_name'=>'Chowdhury','email'=>'iman@example.com',
            'division'=>'Engineering','title'=>'SWE','salary'=>82000
        ];
        $_GET = [];
        $_REQUEST = array_merge($_GET, $_POST);

        $GLOBALS['db'] = new FakePDO(['employees' => []]);

        ob_start();
        include __DIR__ . '/../../admin/backend/actions.php';
        run_actions();
        $out = ob_get_clean();

        $json = json_decode($out, true);
        $this->assertSame(201, http_response_code());
        $this->assertArrayHasKey('id', $json);
        $this->assertGreaterThan(0, $json['id']);
        $this->assertSame('CREATE_EMPLOYEE', $json['audit']['event'] ?? null);
        $this->assertSame(99, $json['audit']['actor_id'] ?? null);
    }
}
?>