<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Disclosure;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Exception\SignatureVerificationFailed;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use K2gl\SdJwt\VerifiedSdJwt;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Verification of the Issuer-signed JWT (RFC 9901 Section 7.1): signature and
 * algorithm policy, `_sd_alg`, time claims, and the MUST-level Disclosure
 * processing rules. Key Binding lives in {@see KeyBindingTest}.
 */
#[CoversClass(SdJwtVerifier::class)]
#[CoversClass(VerifiedSdJwt::class)]
final class SdJwtVerifierTest extends SdJwtTestCase
{
    private const RFC_CLOCK = 1748537300; // shortly after the RFC KB-JWT's iat

    public function testClockLeewayIsHonoured(): void
    {
        // arrange: exp is 10 seconds in the past, but leeway covers it
        $jwt = self::issuerSigner()->sign(payload: ['exp' => 1000]);
        $verifier = new SdJwtVerifier(clock: 1010, clockLeewaySeconds: 30);

        // act
        $claims = $verifier->verify($jwt . '~', self::issuerKey())->claims();

        // assert
        fact($claims)->count(1)->arrayHasKey('exp');
    }

    public function testVerifyRejectsAnSdJwtKb(): void
    {
        // act + assert
        fact(fn () => $this->verifier()->verify(self::fixture('rfc9901/presentation-sd-jwt-kb.txt'), self::rfcIssuerKey()))
            ->throws(InvalidSdJwtException::class);
    }

    public function testTamperedIssuerSignatureIsRejected(): void
    {
        // arrange
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt');
        [$jwt, $rest] = explode('~', $compact, 2);
        $tampered = substr($jwt, 0, -2) . 'AA' . '~' . $rest;

        // act + assert
        fact(fn () => $this->verifier()->verify($tampered, self::rfcIssuerKey()))
            ->throws(SignatureVerificationFailed::class);
    }

    public function testDisallowedAlgorithmIsRejected(): void
    {
        // arrange: the RFC example is ES256, but only EdDSA is allowed
        $verifier = new SdJwtVerifier(allowedAlgorithms: ['EdDSA'], clock: self::RFC_CLOCK);

        // act + assert
        fact(fn () => $verifier->verify(self::fixture('rfc9901/issuance-sd-jwt.txt'), self::rfcIssuerKey()))
            ->throws(SignatureVerificationFailed::class, 'ES256');
    }

    public function testAlgNoneIsRejected(): void
    {
        // arrange
        $header = Base64Url::encode('{"alg":"none"}');
        $payload = Base64Url::encode('{"sub":"user"}');
        $compact = $header . '.' . $payload . '.' . Base64Url::encode('sig') . '~';

        // act + assert
        fact(fn () => $this->verifier()->verify($compact, self::rfcIssuerKey()))
            ->throws(SignatureVerificationFailed::class);
    }

    public function testUnsupportedSdAlgIsRejected(): void
    {
        // arrange
        $jwt = self::issuerSigner()->sign(payload: ['_sd_alg' => 'sha3-256']);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class, '_sd_alg');
    }

    public function testExpiredSdJwtIsRejected(): void
    {
        // arrange
        $jwt = self::issuerSigner()->sign(payload: ['exp' => 1000]);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class, 'exp');
    }

    public function testNotYetValidSdJwtIsRejected(): void
    {
        // arrange
        $jwt = self::issuerSigner()->sign(payload: ['nbf' => PHP_INT_MAX]);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class, 'nbf');
    }

    public function testUnreferencedDisclosureIsRejected(): void
    {
        // arrange: a Disclosure whose digest appears nowhere in the payload
        $stray = Disclosure::forProperty(salt: 's-1', claimName: 'x', value: 1);
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt') . $stray->encoded . '~';

        // act + assert
        fact(fn () => $this->verifier()->verify($compact, self::rfcIssuerKey()))
            ->throws(InvalidSdJwtException::class, 'not referenced');
    }

    public function testDuplicateDisclosureIsRejected(): void
    {
        // arrange: the same Disclosure sent twice
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt');
        $first = explode('~', $compact)[1];

        // act + assert
        fact(fn () => $this->verifier()->verify($compact . $first . '~', self::rfcIssuerKey()))
            ->throws(InvalidSdJwtException::class, 'more than once');
    }

    public function testDuplicateDigestIsRejected(): void
    {
        // arrange: the same digest embedded at two levels of the payload
        $disclosure = Disclosure::forProperty(salt: 's-1', claimName: 'a', value: 1);
        $digest = $disclosure->digest();
        $jwt = self::issuerSigner()->sign(payload: [
            '_sd' => [$digest],
            'nested' => ['_sd' => [$digest]],
            '_sd_alg' => 'sha-256',
        ]);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class, 'more than once');
    }

    public function testReservedClaimNameInDisclosureIsRejected(): void
    {
        // arrange: built by hand to bypass the forProperty() guard
        $encoded = Base64Url::encode('["s-1", "_sd", ["boom"]]');
        $digest = Base64Url::encode(hash('sha256', $encoded, true));
        $jwt = self::issuerSigner()->sign(payload: ['_sd' => [$digest], '_sd_alg' => 'sha-256']);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~' . $encoded . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class, 'reserved');
    }

    public function testClaimNameCollisionIsRejected(): void
    {
        // arrange: a disclosed claim collides with a plaintext one at the same level
        $disclosure = Disclosure::forProperty(salt: 's-1', claimName: 'given_name', value: 'Mallory');
        $jwt = self::issuerSigner()->sign(payload: [
            'given_name' => 'John',
            '_sd' => [$disclosure->digest()],
            '_sd_alg' => 'sha-256',
        ]);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class, 'already exists');
    }

    public function testArrayDisclosureInSdArrayIsRejected(): void
    {
        // arrange: an array-element Disclosure referenced from an object's _sd
        $disclosure = Disclosure::forArrayElement(salt: 's-1', value: 'US');
        $jwt = self::issuerSigner()->sign(payload: ['_sd' => [$disclosure->digest()], '_sd_alg' => 'sha-256']);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class);
    }

    public function testPropertyDisclosureInArrayElementIsRejected(): void
    {
        // arrange: an object-property Disclosure referenced from an array element
        $disclosure = Disclosure::forProperty(salt: 's-1', claimName: 'a', value: 1);
        $jwt = self::issuerSigner()->sign(payload: [
            'list' => [(object) ['...' => $disclosure->digest()]],
            '_sd_alg' => 'sha-256',
        ]);

        // act + assert
        fact(fn () => (new SdJwtVerifier)->verify($jwt . '~' . $disclosure->encoded . '~', self::issuerKey()))
            ->throws(InvalidSdJwtException::class);
    }

    private function verifier(): SdJwtVerifier
    {
        return new SdJwtVerifier(clock: self::RFC_CLOCK);
    }
}
