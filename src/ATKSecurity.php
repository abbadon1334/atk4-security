<?php

declare(strict_types=1);

namespace Abbadon1334\ATKSecurity;

use Abbadon1334\ATKSecurity\Bruteforce\Bruteforce;
use Abbadon1334\ATKSecurity\CrossSiteRequestForgery\CSRF;
use Abbadon1334\ATKSecurity\IntrusionDetection\IDS;
use atk4\core\AppScopeTrait;
use atk4\core\DIContainerTrait;
use atk4\core\HookTrait;
use atk4\core\InitializerTrait;
use atk4\data\Model;
use atk4\ui\App;
use atk4\ui\Exception;
use atk4\ui\Form;
use atk4\ui\FormField\Hidden;
use Zend\Diactoros\ServerRequestFactory;

class ATKSecurity
{
    use AppScopeTrait;
    use DIContainerTrait;
    use HookTrait;
    use InitializerTrait {
        init as _init;
    }

    /** @var App */
    public $app;

    /* IDS Injections */
    /** @var bool auto check intrusion detection */
    public $intrusion_detection_check = true;
    /** @var int threshold level for evaluate intrusion */
    public $intrusion_detection_level = 8;
    /** @var bool if intrusion detected use atk hook */
    public $intrusion_detection_hook = true;
    /** @var bool if intrusion detected raise exception */
    public $intrusion_detection_raise = true;
    /** @var bool if intrusion detected exit process */
    public $intrusion_detection_abort = true;

    /* CSRF Injections */
    /** @var string session prefix for CSRF */
    public $csrf_prefix = 'CSRF';
    /** @var string CSRF hash algo */
    public $csrf_algo = 'sha256';

    /* Bruteforce Injections */
    /** @var bool on bruteforce use sleep function */
    public $bruteforce_use_sleep = true;
    /** @var bool on bruteforce use atk hook */
    public $bruteforce_use_hook  = true;
    /** @var int on bruteforce raise exception when >= attempt number */
    public $bruteforce_raise_on  = false;
    /** @var int on bruteforce exit process when >= attempt number */
    public $bruteforce_abort_on  = false;
    /** @var array rules - attempt_number => seconds_to_wait */
    public $bruteforce_throttle_rules = [
        /* until 4 - 0 wait time */
        4 => 2,
        5 => 4,
        6 => 6,
        7 => 8,
        8 => 16,
        9 => 30,
    ];

    /** @var \Zend\Diactoros\ServerRequest */
    private $request;

    /** @var CSRF */
    private $CSRF;

    public function __construct($options = [])
    {
        $this->setDefaults($options);
    }

    public function init(): void
    {
        $this->request = ServerRequestFactory::fromGlobals();

        $this->CSRF = new CSRF([
            'prefix' => $this->csrf_prefix,
            'algo'   => $this->csrf_algo,
        ]);

        if ($this->intrusion_detection_check) {
            $this->checkIntrusionDetection();
        }
    }

    /* IDS */
    public function checkIntrusionDetection(): void
    {
        $IDS = new IDS([
            'threshold' => $this->intrusion_detection_level,
        ]);

        $intrusion_detected = $IDS->check($this->request);

        if ($intrusion_detected) {
            $this->onDetectIntrusion($IDS->getViolations());
        }
    }

    /* CSRF */
    public function createCSRF(string $identifier): string
    {
        return $this->CSRF->create($identifier);
    }

    public function forgetCSRF(string $identifier): void
    {
        $this->CSRF->forget($identifier);
    }

    public function validateCSRF(string $identifier, string $token): bool
    {
        return $this->CSRF->validate($identifier, $token);
    }

    public function addFieldCSRF(Form $form, string $field_name = 'CSRF'): void
    {
        $this->createCSRF($form->name);
        $form->addField($field_name, Hidden::class, [
            'never_persist' => true,
        ]);

        $this->addHook('beforeSave', function (Model $m, $form) use ($field_name): void {
            if ($this->validateCSRF($form->name, $m[$field_name])) {
                $this->forgetCSRF($form->name);
                unset($m[$field_name]);

                return;
            }

            $m->breakHook('CSRF');
        }, $form, -100);
    }

    /* Bruteforce */
    public function validateRequestBruteforce(): void
    {
        $bruteforce = new Bruteforce([
            'throttle_rules' => $this->bruteforce_throttle_rules,
        ]);

        $bruteforce->check($this->request);

        $attempt_number = $bruteforce->getAttemptNumber();
        $throttle_time  = $bruteforce->getThrottleTime();

        if (false !== $this->bruteforce_raise_on) {
            if ($this->bruteforce_raise_on > $attempt_number) {
                throw new Exception(['Bruteforce detected',
                    'attempt' => $attempt_number,
                ]);
            }
        }

        if (false !== $this->bruteforce_abort_on) {
            if ($this->bruteforce_abort_on > $attempt_number) {
                $this->app->terminate('Bruteforce detected ('.$attempt_number.')');
            }
        }

        if ($this->bruteforce_use_hook) {
            $this->hook('onBruteforce', [
                $attempt_number,
                $throttle_time,
            ]);
        }

        if ($this->bruteforce_use_sleep) {
            sleep($throttle_time);
        }
    }

    protected function onDetectIntrusion($violations): void
    {
        if ($this->intrusion_detection_hook) {
            $this->hook('onIntrusion', $violations);
        }

        if ($this->intrusion_detection_raise) {
            throw new Exception(
                [
                    'Intrusion detected',
                    'Violations' => $violations,
                ]
            );
        }

        if ($this->intrusion_detection_abort) {
            $this->app->terminate('INTRUSION DETECTED');
        }
    }
}
