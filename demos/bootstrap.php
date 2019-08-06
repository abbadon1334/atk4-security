<?php

declare(strict_types=1);

use atk4\schema\Migration;
use atk4\ui\Layout\Centered;
use SebastianBergmann\CodeCoverage\CodeCoverage;
use SebastianBergmann\CodeCoverage\Report\PHP;

require_once '../vendor/autoload.php';

ini_set('date.timezone', 'Europe/Rome');
ini_set('session.save_path', '/tmp');

$app = new \atk4\ui\App([
    'title' => 'ATK - Security DEMO',
]);
$app->initLayout(Centered::class);
$app->dbConnect('sqlite::memory:');

/* COVERAGE - SETUP - START */
$coverage = new CodeCoverage();
$coverage->filter()->addDirectoryToWhitelist('../src');

$app->addHook('beforeExit', function () use ($coverage): void {
    $coverage->stop();

    $writer = new PHP();

    $prefix = basename($_SERVER['SCRIPT_NAME'], '.php');
    $writer->process($coverage, dirname(realpath(__FILE__)).'/../coverage/'.uniqid($prefix, false).'.cov');
});

$coverage->start($_SERVER['SCRIPT_NAME']);
/* COVERAGE - SETUP - END */

/* MODEL - DEF - START */

class User extends \atk4\data\Model
{
    public $table = 'user';

    public function init(): void
    {
        parent::init();
        $this->addField('username');
        $this->addField('email');
    }
}

Migration::getMigration(new User($app->db))->migrate();
/* MODEL - DEF - END */
