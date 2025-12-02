<?php
// Tell actions.php we are in tests (prevents any auto-run you might have later)
if (!defined('TEST_MODE')) { define('TEST_MODE', true); }

ini_set('display_errors', '1');
error_reporting(E_ALL);

if (session_status() === PHP_SESSION_NONE) { session_start(); }

if (!function_exists('json_response')) {
    function json_response(int $code, array $payload): void {
        http_response_code($code);
        header('Content-Type: application/json');
        echo json_encode($payload);
    }
}

require_once __DIR__ . '/fakes/FakePDO.php';
