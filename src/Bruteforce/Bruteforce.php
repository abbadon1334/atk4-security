<?php

declare(strict_types=1);

namespace Abbadon1334\ATKSecurity\Bruteforce;

use atk4\core\DIContainerTrait;
use atk4\core\SessionTrait;
use atk4\ui\Exception;
use Zend\Diactoros\ServerRequest;

class Bruteforce
{
    use DIContainerTrait;
    use SessionTrait {
        forget as _forget;
    }

    public $prefix = 'BTF';

    public $throttle_rules = [
        /* until 4 - 0 wait time */
        4 => 2,
        5 => 4,
        6 => 6,
        7 => 8,
        8 => 16,
        9 => 30,
    ];

    private $attempt;
    private $attempt_max = 0;

    private $path_identifier;

    public function __construct(?array $defaults=null)
    {
        $this->setDefaults($defaults ?? []);

        if (empty($this->throttle_rules)) {
            throw new Exception(['Throttle rules cannto be empty']);
        }

        // prepare throttle rules
        $attempt_count = 0;
        $attempt_wait  = 0;
        while (true) {
            if (!isset($this->throttle_rules[$attempt_count])) {
                $this->throttle_rules[$attempt_count] = $attempt_wait;
            }
            $attempt_wait = $this->throttle_rules[$attempt_count];
            $attempt_count++;
        }

        $this->attempt_max = count($this->throttle_rules);
    }

    public function check(ServerRequest $request): bool
    {
        $this->path_identifier = $this->getIdentifierWithPrefix($request->getUri()->getPath());

        $this->attemptCountProcess();
        $this->attemptCountIncrementOrMAX();
        $this->checkBruteforce();
    }

    public function attemptCountProcess(): void
    {
        $this->attempt = $this->recall($this->path_identifier, 0);
    }

    public function attemptCountIncrementOrMAX(): void
    {
        $this->attempt++;

        if ($this->attempt > $this->attempt_max) {
            $this->attempt = $this->attempt_max;
        }

        $this->memorize($this->path_identifier, $this->attempt);
    }

    public function getAttemptNumber(): int
    {
        if (null === $this->attempt) {
            throw new Exception('Bruteforce->check was not called');
        }

        return $this->attempt;
    }

    public function getThrottleTime(): int
    {
        if (null === $this->attempt) {
            throw new Exception('Bruteforce->check was not called');
        }

        return $this->throttle_rules[$this->attempt];
    }

    private function getIdentifierWithPrefix(string $identifier): string
    {
        return $this->prefix.'.'.$identifier;
    }
}
