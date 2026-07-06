<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Disclosure;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Exception\KeyBindingVerificationFailed;
use K2gl\SdJwt\Exception\SignatureVerificationFailed;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\VerifiedSdJwt;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(SdJwtVerifier::class)]
#[CoversClass(KeyBinding::class)]
#[CoversClass(VerifiedSdJwt::class)]
final class SdJwtVerifierTest extends SdJwtTestCase
{
    private const RFC_CLOCK = 1748537300; // shortly after the RFC KB-JWT's iat

    private function verifier(): SdJwtVerifier
    {
        return new SdJwtVerifier(clock: self::RFC_CLOCK);
    }

    public function testVerifiesTheRfcIssuanceExample(): void
    {
        $verified = $this->verifier()->verify(self::fixture('rfc9901/issuance-sd-jwt.txt'), self::rfcIssuerKey());
        $claims = $verified->claims();

        self::assertSame('https://issuer.example.com', $claims['iss']);
        self::assertSame('John', $claims['given_name']);
        self::assertSame('Doe', $claims['family_name']);
        self::assertSame('johndoe@example.com', $claims['email']);
        self::assertSame('+1-202-555-0101', $claims['phone_number']);
        self::assertTrue($claims['phone_number_verified']);
        self::assertSame('1940-01-01', $claims['birthdate']);
        self::assertSame(1570000000, $claims['updated_at']);
        self::assertSame(['US', 'DE'], $claims['nationalities']);
        self::assertSame(
            ['street_address' => '123 Main St', 'locality' => 'Anytown', 'region' => 'Anystate', 'country' => 'US'],
            $claims['address'],
        );
        self::assertArrayNotHasKey('_sd', $claims);
        self::assertArrayNotHasKey('_sd_alg', $claims);
        self::assertNull($verified->keyBindingPayload());
    }

    /** The full Section 5.2 flow: SD-JWT+KB against the RFC's expected payload. */
    public function testVerifiesTheRfcPresentationExample(): void
    {
        $verified = $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );

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

        self::assertEquals($expected, $verified->claims());

        $kb = $verified->keyBindingPayload();
        self::assertNotNull($kb);
        self::assertSame('0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY', $kb->sd_hash);
        self::assertSame(1748537244, $kb->iat);
    }

    public function testVerifyRejectsAnSdJwtKb(): void
    {
        $this->expectException(InvalidSdJwtException::class);

        $this->verifier()->verify(self::fixture('rfc9901/presentation-sd-jwt-kb.txt'), self::rfcIssuerKey());
    }

    public function testRequiredKeyBindingRejectsAPlainSdJwt(): void
    {
        $this->expectException(KeyBindingVerificationFailed::class);

        $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/issuance-sd-jwt.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );
    }

    public function testNotRequiredIgnoresThePresentKbJwt(): void
    {
        $verified = $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::notRequired(),
        );

        self::assertNull($verified->keyBindingPayload());
        self::assertSame('Doe', $verified->claims()['family_name']);
    }

    public function testWrongAudienceIsRejected(): void
    {
        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('aud');

        $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://other.example.org', nonce: '1234567890'),
        );
    }

    public function testWrongNonceIsRejected(): void
    {
        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('nonce');

        $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: 'other'),
        );
    }

    public function testStaleKeyBindingIsRejected(): void
    {
        $verifier = new SdJwtVerifier(clock: self::RFC_CLOCK + 86400);

        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('iat');

        $verifier->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );
    }

    public function testSdHashMismatchIsRejected(): void
    {
        // Drop one Disclosure from the presentation: sd_hash no longer matches.
        $parts = explode('~', self::fixture('rfc9901/presentation-sd-jwt-kb.txt'));
        $kbJwt = array_pop($parts);
        array_splice($parts, 1, 1);
        $tampered = implode('~', $parts) . '~' . $kbJwt;

        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('sd_hash');

        $this->verifier()->verifyPresentation(
            $tampered,
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );
    }

    public function testTamperedIssuerSignatureIsRejected(): void
    {
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt');
        [$jwt, $rest] = explode('~', $compact, 2);
        $tampered = substr($jwt, 0, -2) . 'AA' . '~' . $rest;

        $this->expectException(SignatureVerificationFailed::class);

        $this->verifier()->verify($tampered, self::rfcIssuerKey());
    }

    public function testDisallowedAlgorithmIsRejected(): void
    {
        $verifier = new SdJwtVerifier(allowedAlgorithms: ['EdDSA'], clock: self::RFC_CLOCK);

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('ES256');

        $verifier->verify(self::fixture('rfc9901/issuance-sd-jwt.txt'), self::rfcIssuerKey());
    }

    public function testAlgNoneIsRejected(): void
    {
        $header = Base64Url::encode('{"alg":"none"}');
        $payload = Base64Url::encode('{"sub":"user"}');
        $compact = $header . '.' . $payload . '.' . Base64Url::encode('sig') . '~';

        $this->expectException(SignatureVerificationFailed::class);

        $this->verifier()->verify($compact, self::rfcIssuerKey());
    }

    public function testUnsupportedSdAlgIsRejected(): void
    {
        $jwt = self::issuerSigner()->sign(payload: ['_sd_alg' => 'sha3-256']);

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('_sd_alg');

        (new SdJwtVerifier)->verify($jwt . '~', self::issuerKey());
    }

    public function testExpiredSdJwtIsRejected(): void
    {
        $jwt = self::issuerSigner()->sign(payload: ['exp' => 1000]);

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('exp');

        (new SdJwtVerifier)->verify($jwt . '~', self::issuerKey());
    }

    public function testNotYetValidSdJwtIsRejected(): void
    {
        $jwt = self::issuerSigner()->sign(payload: ['nbf' => PHP_INT_MAX]);

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('nbf');

        (new SdJwtVerifier)->verify($jwt . '~', self::issuerKey());
    }

    public function testClockLeewayIsHonoured(): void
    {
        $jwt = self::issuerSigner()->sign(payload: ['exp' => 1000]);
        $verifier = new SdJwtVerifier(clock: 1010, clockLeewaySeconds: 30);

        self::assertSame([], array_diff_key(
            $verifier->verify($jwt . '~', self::issuerKey())->claims(),
            ['exp' => true],
        ));
    }

    public function testUnreferencedDisclosureIsRejected(): void
    {
        $stray = Disclosure::forProperty(salt: 's-1', claimName: 'x', value: 1);
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt') . $stray->encoded . '~';

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('not referenced');

        $this->verifier()->verify($compact, self::rfcIssuerKey());
    }

    public function testDuplicateDisclosureIsRejected(): void
    {
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt');
        $first = explode('~', $compact)[1];

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('more than once');

        $this->verifier()->verify($compact . $first . '~', self::rfcIssuerKey());
    }

    public function testDuplicateDigestIsRejected(): void
    {
        $disclosure = Disclosure::forProperty(salt: 's-1', claimName: 'a', value: 1);
        $digest = $disclosure->digest();
        $jwt = self::issuerSigner()->sign(payload: [
            '_sd' => [$digest],
            'nested' => ['_sd' => [$digest]],
            '_sd_alg' => 'sha-256',
        ]);

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('more than once');

        (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey());
    }

    public function testReservedClaimNameInDisclosureIsRejected(): void
    {
        // Built by hand to bypass the forProperty() guard.
        $encoded = Base64Url::encode('["s-1", "_sd", ["boom"]]');
        $digest = Base64Url::encode(hash('sha256', $encoded, true));
        $jwt = self::issuerSigner()->sign(payload: ['_sd' => [$digest], '_sd_alg' => 'sha-256']);

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('reserved');

        (new SdJwtVerifier)->verify($jwt . '~' . $encoded . '~', self::issuerKey());
    }

    public function testClaimNameCollisionIsRejected(): void
    {
        $disclosure = Disclosure::forProperty(salt: 's-1', claimName: 'given_name', value: 'Mallory');
        $jwt = self::issuerSigner()->sign(payload: [
            'given_name' => 'John',
            '_sd' => [$disclosure->digest()],
            '_sd_alg' => 'sha-256',
        ]);

        $this->expectException(InvalidSdJwtException::class);
        $this->expectExceptionMessage('already exists');

        (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey());
    }

    public function testArrayDisclosureInSdArrayIsRejected(): void
    {
        $disclosure = Disclosure::forArrayElement(salt: 's-1', value: 'US');
        $jwt = self::issuerSigner()->sign(payload: ['_sd' => [$disclosure->digest()], '_sd_alg' => 'sha-256']);

        $this->expectException(InvalidSdJwtException::class);

        (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey());
    }

    public function testPropertyDisclosureInArrayElementIsRejected(): void
    {
        $disclosure = Disclosure::forProperty(salt: 's-1', claimName: 'a', value: 1);
        $jwt = self::issuerSigner()->sign(payload: [
            'list' => [(object) ['...' => $disclosure->digest()]],
            '_sd_alg' => 'sha-256',
        ]);

        $this->expectException(InvalidSdJwtException::class);

        (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey());
    }

    public function testUndisclosedArrayElementsAreRemoved(): void
    {
        $claims = (new SdJwtVerifier(clock: 1700000000))
            ->verifyPresentation(
                Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'))->disclose('/nationalities/1')->toCompact(),
                self::rfcIssuerKey(),
                KeyBinding::notRequired(),
            )
            ->claims();

        self::assertSame(['DE'], $claims['nationalities']);
    }

    public function testMissingHolderKeyFailsKeyBinding(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue(['given_name' => Sd::hide('John')]); // no cnf

        $compact = Presentation::of($sdJwt)
            ->discloseAll()
            ->withKeyBinding(self::holderSigner(), audience: 'aud', nonce: 'n', issuedAt: 1700000000);

        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('cnf');

        (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $compact,
            self::issuerKey(),
            KeyBinding::required(audience: 'aud', nonce: 'n'),
        );
    }

    public function testKeyBindingAlgorithmMustMatchTheHolderKey(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'cnf' => ['jwk' => self::holderJwk()], // P-256 key...
            'given_name' => Sd::hide('John'),
        ]);

        $compact = Presentation::of($sdJwt)
            ->discloseAll()
            // ...but the KB-JWT is signed with Ed25519.
            ->withKeyBinding(
                \K2gl\SdJwt\Jws\JwsSigner::ed25519(sodium_crypto_sign_secretkey($keypair)),
                audience: 'aud',
                nonce: 'n',
                issuedAt: 1700000000,
            );

        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('does not match the Holder key');

        (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $compact,
            self::issuerKey(),
            KeyBinding::required(audience: 'aud', nonce: 'n'),
        );
    }

    public function testWrongKbTypIsRejected(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'cnf' => ['jwk' => self::holderJwk()],
            'given_name' => Sd::hide('John'),
        ]);

        // Hand-build the KB-JWT with a wrong typ.
        $presentation = Presentation::of($sdJwt)->discloseAll();
        $sdJwtCompact = $presentation->toCompact();
        $kbJwt = self::holderSigner()->sign(
            payload: [
                'nonce' => 'n',
                'aud' => 'aud',
                'iat' => 1700000000,
                'sd_hash' => \K2gl\SdJwt\Internal\HashAlgorithm::digest('sha-256', $sdJwtCompact),
            ],
            header: ['typ' => 'JWT'],
        );

        $this->expectException(KeyBindingVerificationFailed::class);
        $this->expectExceptionMessage('kb+jwt');

        (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $sdJwtCompact . $kbJwt,
            self::issuerKey(),
            KeyBinding::required(audience: 'aud', nonce: 'n'),
        );
    }
}
