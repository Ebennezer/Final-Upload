<?php
use PHPUnit\Framework\TestCase;

require __DIR__.'/bootstrap.php';

final class RBACTest extends TestCase {
    public function test_employee_cannot_open_mass_update(): void {
        $_SESSION = ['role'=>'Employee','user_id'=>33];
        $_GET = ['action'=>'page','path'=>'/salary/mass-update']; $_POST = [];
        $_REQUEST = array_merge($_GET, $_POST); // IMPORTANT for CLI tests

        ob_start();
        include __DIR__.'/../../admin/backend/actions.php'; // defines run_actions()
        run_actions();                                      // execute
        $out = ob_get_clean();
        $json = json_decode($out, true);

        $this->assertSame(403, http_response_code());
        $this->assertSame('/employee/employee.php', $json['redirect'] ?? null);
        $this->assertSame('ACCESS_DENIED', $json['error'] ?? null);
        $this->assertSame('RBAC_DENIED', $json['audit']['event'] ?? null);
    }

    public function test_admin_can_open_admin_page(): void {
        $_SESSION = ['role'=>'Admin','user_id'=>1];
        $_GET = ['action'=>'page','path'=>'/salary/mass-update']; $_POST = [];
        $_REQUEST = array_merge($_GET, $_POST);

        ob_start();
        include __DIR__.'/../../admin/backend/actions.php';
        run_actions();
        $out = ob_get_clean();
        $json = json_decode($out, true);

        $this->assertSame(200, http_response_code());
        $this->assertSame('OK', $json['status'] ?? null);
    }
}
?>