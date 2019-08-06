<?php

declare(strict_types=1);

namespace Abbadon1334\ATKSecurity\IntrusionDetection;

use atk4\core\DIContainerTrait;
use Zend\Diactoros\ServerRequest;

class IDS
{
    use DIContainerTrait;

    public $threshold = 8;

    private $validator;

    public function __construct(?array $defaults=null)
    {
        $this->setDefaults($defaults ?? []);
    }

    public function check(ServerRequest $request): bool
    {
        $this->validator = new \vakata\ids\IDS();

        $level = $this->validator->analyzeData([
            'GET'  => $request->getQueryParams() ?? [],
            'POST' => $request->getParsedBody() ?? [],
        ],
            $this->threshold
        );

        return $level > $this->threshold;
    }

    public function getViolations(): array
    {
        return $this->validator->getViolations();
    }
}
