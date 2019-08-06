<?php

declare(strict_types=1);

namespace Abbadon1334\ATKSecurity\Tests;

/**
 * @internal
 */
class ATKSecurityTest extends BuiltInWebServerAbstract
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        foreach (glob('coverage/*') as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
    }

    public static function tearDownAfterClass(): void
    {
        exec('vendor/bin/phpcov  merge coverage/ --clover clover.xml');
        parent::tearDownAfterClass();
    }

    public function testAddFieldCSRF(): void
    {
        $response = $this->getResponseFromRequestGET('CSRF.php');
        $this->assertEquals(200, $response->getStatusCode());

        $CSRF1 = $this->getCSRFFromBody($response->getBody()->getContents());
        $this->assertNotNull($CSRF1);

        $response = $this->getResponseFromRequestGET('CSRF.php');
        $this->assertEquals(200, $response->getStatusCode());

        $CSRF2 = $this->getCSRFFromBody($response->getBody()->getContents());
        $this->assertNotNull($CSRF2);

        $this->assertNotEquals($CSRF1, $CSRF2);

        $response = $this->getResponseFromRequestFormPOST(
            'CSRF.php?atk_centered_form_submit=ajax&__atk_callback=1', [
                'CSRF'                     => 'test will give error',
                'username'                 => 'abc',
                'email'                    => 'test',
                'atk_centered_form_submit' => 'submit',
            ]);
        $this->assertEquals(200, $response->getStatusCode());
        $body = $response->getBody()->getContents();
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testValidateRequestBruteforce(): void
    {
        /* @TODO TEST */
    }

    public function testCheckIntrusionDetection(): void
    {
        /* @TODO TEST */
    }

    /**
     * @param string $body
     *
     * @return string|null
     */
    private function getCSRFFromBody(string $body): ?string
    {
        $re = '/CSRF.*value\=\"(.*)\"/m';
        preg_match_all($re, $body, $matches, PREG_SET_ORDER, 0);

        return $matches[0][1] ?? null;
    }
}
