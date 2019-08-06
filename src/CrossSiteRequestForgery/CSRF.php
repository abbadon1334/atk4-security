<?php

declare(strict_types=1);

namespace Abbadon1334\ATKSecurity\CrossSiteRequestForgery;

use atk4\core\DIContainerTrait;
use atk4\core\SessionTrait;

class CSRF
{
    use DIContainerTrait;
    use SessionTrait {
        forget as _forget;
    }

    public $prefix = 'CSRF';
    public $algo   = 'sha256';

    public function __construct($options = [])
    {
        $this->setDefaults($options);
    }

    public function create(string $identifier): string
    {
        $csrf = hash($this->algo, bin2hex(random_bytes(64)));
        $this->memorize(
            $this->getIdentifierWithPrefix($identifier),
            $csrf
        );

        return $csrf;
    }

    public function forget(string $identifier): void
    {
        $this->_forget($identifier);
    }

    public function get(string $identifier): ?string
    {
        return $this->recall($this->getIdentifierWithPrefix($identifier));
    }

    public function validate(string $identifier, string $token): bool
    {
        return hash_equals($this->get($identifier), $token);
    }

    private function getIdentifierWithPrefix(string $identifier): string
    {
        return $this->prefix.'.'.$identifier;
    }
}
