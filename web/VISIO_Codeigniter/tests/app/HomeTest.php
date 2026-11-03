<?php
namespace Tests;
use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\FeatureTestTrait;
class HomeTest extends CIUnitTestCase
{
    use FeatureTestTrait;

    public function testPaginaInicialRespondeCorretamente(): void
    {
        $resultado = $this->call('get', '/');

        $resultado->assertStatus(200);
    }
}