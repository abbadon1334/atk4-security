<?php

declare(strict_types=1);

use atk4\ui\Form;

require_once 'bootstrap.php';

$app->add($security = new Abbadon1334\ATKSecurity\ATKSecurity([
    'intrusion_detection_check' => false,
]));

$app->add($form = new Form());
$form->setModel($model = new User($app->db));

$model->tryLoad(1);

$security->addFieldCSRF($form);

$app->run();
