<?php
// Minimal fake DB so tests run without a real database.
class FakePDO {
    private array $data;
    public function __construct(array $data = []) { $this->data = $data; }
    public function prepare($sql) { return new FakeStmt($this->data, $sql); }
    public function query($sql)   { $s = new FakeStmt($this->data, $sql); $s->execute(); return $s; }
}
class FakeStmt {
    private array $data; private string $sql; private array $params=[]; private array $result=[];
    public function __construct(array $data, string $sql) { $this->data=$data; $this->sql=$sql; }
    public function bindValue($k,$v,$t=null){ $this->params[$k]=$v; }
    public function execute($params=null){
        if ($params) $this->params=$params;

        // Super-simplified router by SQL content for our tests.
        if (stripos($this->sql, 'FROM employees') !== false) {
            $rows = $this->data['employees'] ?? [];
            if (isset($this->params[':q'])) {
                $q = strtolower(trim($this->params[':q'], '%'));
                $rows = array_values(array_filter($rows, fn($r)=>str_contains(strtolower($r['last_name']), $q)));
            }
            if (isset($this->params[':division'])) {
                $rows = array_values(array_filter($rows, fn($r)=>$r['division']===$this->params[':division']));
            }
            if (isset($this->params[':status'])) {
                $rows = array_values(array_filter($rows, fn($r)=>$r['status']===$this->params[':status']));
            }
            $this->result = $rows;
        } elseif (stripos($this->sql, 'INSERT INTO employees') !== false) {
            $id = count(($this->data['employees'] ?? [])) + 1;
            $this->result = [['id'=>$id]];
        } elseif (stripos($this->sql, 'UPDATE employees SET salary') !== false) {
            $this->result = [['ok'=>true]];
        } elseif (stripos($this->sql, 'FROM payroll') !== false || stripos($this->sql,'GROUP BY title')!==false) {
            $this->result = $this->data['payrollAgg'] ?? [];
        } elseif (stripos($this->sql, 'INSERT INTO audit') !== false) {
            $this->result = [['ok'=>true]];
        }
        return true;
    }
    public function fetchAll($mode=null){ return $this->result; }
    public function fetch($mode=null){ return $this->result[0] ?? false; }
}
