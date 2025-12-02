<?php
use PHPUnit\Framework\TestCase;
require __DIR__.'/bootstrap.php';

final class ViewEmployeesTest extends TestCase {
    public function test_manager_can_filter_employees_and_get_200_json(): void {
        $_SESSION = ['role' => 'Manager'];
        $_GET = [
            'action'   => 'searchEmployees',
            'q'        => 'Chowdhury',
            'division' => 'Engineering',
            'status'   => 'Active',
            'page'     => 1, 'per_page' => 10
        ];
        $_POST = [];
        $_REQUEST = array_merge($_GET, $_POST);

        // Fake DB with some rows (optional for the stub)
        $GLOBALS['db'] = new FakePDO([
            'employees' => [
                ['id'=>1,'first_name'=>'I.','last_name'=>'Chowdhury','division'=>'Engineering','status'=>'Active'],
                ['id'=>2,'first_name'=>'Ana','last_name'=>'Chowdhury','division'=>'HR','status'=>'Active'],
                ['id'=>3,'first_name'=>'Ivan','last_name'=>'Chen','division'=>'Engineering','status'=>'Inactive'],
            ]
        ]);

        ob_start();
        include __DIR__ . '/../../admin/backend/actions.php';
        run_actions();
        $out = ob_get_clean();

        $this->assertNotEmpty($out, 'Empty response');
        $json = json_decode($out, true);
        $this->assertIsArray($json);
        $this->assertSame(200, http_response_code());
        $this->assertArrayHasKey('data', $json);
        $this->assertArrayHasKey('pagination', $json);
    }
}
?>