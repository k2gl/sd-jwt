<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use K2gl\SdJwt\VerifiedSdJwt;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The worked examples of RFC 9901 Section 5, verified end to end against the
 * spec's own expected outputs.
 */
#[CoversClass(SdJwtVerifier::class)]
#[CoversClass(VerifiedSdJwt::class)]
#[CoversClass(KeyBinding::class)]
final class Rfc9901ExamplesTest extends SdJwtTestCase
{
    private const RFC_CLOCK = 1748537300; // shortly after the RFC KB-JWT's iat

    public function testVerifiesTheIssuanceExample(): void
    {
        // act
        $verified = $this->verifier()->verify(self::fixture('rfc9901/issuance-sd-jwt.txt'), self::rfcIssuerKey());
        $claims = $verified->claims();

        // assert: every disclosed claim reconstructs to its RFC value
        fact($claims['iss'])->is('https://issuer.example.com');
        fact($claims['given_name'])->is('John');
        fact($claims['family_name'])->is('Doe');
        fact($claims['email'])->is('johndoe@example.com');
        fact($claims['phone_number'])->is('+1-202-555-0101');
        fact($claims['phone_number_verified'])->true();
        fact($claims['birthdate'])->is('1940-01-01');
        fact($claims['updated_at'])->is(1570000000);
        fact($claims['nationalities'])->is(['US', 'DE']);
        fact($claims['address'])->is(
            ['street_address' => '123 Main St', 'locality' => 'Anytown', 'region' => 'Anystate', 'country' => 'US'],
        );

        // assert: the processing artifacts are gone and there is no Key Binding
        fact($claims)->arrayNotHasKey('_sd');
        fact($claims)->arrayNotHasKey('_sd_alg');
        fact($verified->keyBindingPayload())->null();
    }

    /** The full Section 5.2 flow: SD-JWT+KB against the RFC's expected payload. */
    public function testVerifiesThePresentationExample(): void
    {
        // arrange
        $expected = [
            'iss' => 'https://issuer.example.com',
            'iat' => 1683000000,
            'exp' => 1883000000,
            'sub' => 'user_42',
            'nationalities' => ['US'],
            'cnf' => [
                'jwk' => [
                    'kty' => 'EC',
                    'crv' => 'P-256',
                    'x' => 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
                    'y' => 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
                ],
            ],
            'family_name' => 'Doe',
            'address' => [
                'street_address' => '123 Main St',
                'locality' => 'Anytown',
                'region' => 'Anystate',
                'country' => 'US',
            ],
            'given_name' => 'John',
        ];

        // act
        $verified = $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );

        // assert: the processed payload (key order differs from the RFC listing — compare by value)
        fact($verified->claims())->equals($expected);

        // assert: the verified Key Binding payload
        $kb = $verified->keyBindingPayload();
        fact($kb)->notNull();
        fact($kb->sd_hash)->is('0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY');
        fact($kb->iat)->is(1748537244);
    }

    public function testNotRequiredIgnoresThePresentKbJwt(): void
    {
        // act
        $verified = $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::notRequired(),
        );

        // assert
        fact($verified->keyBindingPayload())->null();
        fact($verified->claims()['family_name'])->is('Doe');
    }

    public function testUndisclosedArrayElementsAreRemoved(): void
    {
        // act
        $claims = (new SdJwtVerifier(clock: 1700000000))
            ->verifyPresentation(
                Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'))->disclose('/nationalities/1')->toCompact(),
                self::rfcIssuerKey(),
                KeyBinding::notRequired(),
            )
            ->claims();

        // assert: only the disclosed nationality survives, the other is dropped
        fact($claims['nationalities'])->is(['DE']);
    }

    private function verifier(): SdJwtVerifier
    {
        return new SdJwtVerifier(clock: self::RFC_CLOCK);
    }
}
