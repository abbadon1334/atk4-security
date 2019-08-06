<?php

declare(strict_types=1);

namespace Abbadon1334\ATKSecurity\Tests;

use GuzzleHttp\Client;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\Process\Process;

abstract class BuiltInWebServerAbstract extends TestCase
{
    protected static $process;

    protected static $host = '127.0.0.1';
    protected static $port = 9687;

    /** @var bool set the app->call_exit in demo */
    protected static $app_def_call_exit = true;

    /** @var bool set the app->caught_exception in demo */
    protected static $app_def_caught_exception = true;

    protected static $webserver_root = 'demos/';

    public static function setUpBeforeClass(): void
    {
        // The command to spin up the server
        self::$process = Process::fromShellCommandline('php -S '.self::$host.':'.self::$port.' -t '.getcwd().' -d session.save_path=/tmp');

        // Disabling the output, otherwise the process might hang after too much output
        self::$process->disableOutput();

        // Actually execute the command and start the process
        self::$process->start();

        sleep(1);
    }

    protected function getResponseFromRequestFormPOST($path, $data): ResponseInterface
    {
        return $this->getClient()->request('POST', $this->getPathWithAppVars($path), ['form_params' => $data]);
    }

    protected function getResponseFromRequestGET($path): ResponseInterface
    {
        return $this->getClient()->request('GET', $this->getPathWithAppVars($path));
    }

    private function getClient(): Client
    {
        // Creating a Guzzle Client with the base_uri, so we can use a relative
        // path for the requests.
        return new Client(['base_uri' => 'http://localhost:'.self::$port]);
    }

    private function getPathWithAppVars($path)
    {
        $path .= false === strpos($path, '?') ? '?' : '&';
        $path .= 'APP_CALL_EXIT='.((int) static::$app_def_call_exit).'&APP_CATCH_EXCEPTIONS='.((int) static::$app_def_caught_exception);

        return self::$webserver_root.$path;
    }
}
