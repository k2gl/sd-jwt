<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\KeyBindingVerificationFailed;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Key Binding validation (RFC 9901 Section 7.3): the KB-JWT must be present
 * when required, signed by the Holder key in `cnf`, and bound to this exact
 * transaction and presentation.
 */
#[CoversClass(SdJwtVerifier::class)]
#[CoversClass(KeyBinding::class)]
final class KeyBindingTest extends SdJwtTestCase
{
    private const RFC_CLOCK = 1748537300; // shortly after the RFC KB-JWT's iat

    public function testRequiredKeyBindingRejectsAPlainSdJwt(): void
    {
        // act + assert
        fact(fn () => $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/issuance-sd-jwt.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        ))->throws(KeyBindingVerificationFailed::class);
    }

    public function testWrongAudienceIsRejected(): void
    {
        // act + assert
        fact(fn () => $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://other.example.org', nonce: '1234567890'),
        ))->throws(KeyBindingVerificationFailed::class, 'aud');
    }

    public function testWrongNonceIsRejected(): void
    {
        // act + assert
        fact(fn () => $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: 'other'),
        ))->throws(KeyBindingVerificationFailed::class, 'nonce');
    }

    public function testStaleKeyBindingIsRejected(): void
    {
        // arrange
        $verifier = new SdJwtVerifier(clock: self::RFC_CLOCK + 86400);

        // act + assert
        fact(fn () => $verifier->verifyPresentation(
            self::fixture('rfc9901/presentation-sd-jwt-kb.txt'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        ))->throws(KeyBindingVerificationFailed::class, 'iat');
    }

    public function testSdHashMismatchIsRejected(): void
    {
        // arrange: drop one Disclosure from the presentation so sd_hash no longer matches
        $parts = explode('~', self::fixture('rfc9901/presentation-sd-jwt-kb.txt'));
        $kbJwt = array_pop($parts);
        array_splice($parts, 1, 1);
        $tampered = implode('~', $parts) . '~' . $kbJwt;

        // act + assert
        fact(fn () => $this->verifier()->verifyPresentation(
            $tampered,
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        ))->throws(KeyBindingVerificationFailed::class, 'sd_hash');
    }

    public function testMissingHolderKeyFailsKeyBinding(): void
    {
        // arrange: an SD-JWT without a cnf claim cannot anchor a Key Binding
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue(['given_name' => Sd::hide('John')]);

        $compact = Presentation::of($sdJwt)
            ->discloseAll()
            ->withKeyBinding(self::holderSigner(), audience: 'aud', nonce: 'n', issuedAt: 1700000000);

        // act + assert
        fact(fn () => (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $compact,
            self::issuerKey(),
            KeyBinding::required(audience: 'aud', nonce: 'n'),
        ))->throws(KeyBindingVerificationFailed::class, 'cnf');
    }

    public function testKeyBindingAlgorithmMustMatchTheHolderKey(): void
    {
        // arrange: the cnf holds a P-256 key, but the KB-JWT is signed with Ed25519
        $keypair = sodium_crypto_sign_keypair();
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'cnf' => ['jwk' => self::holderJwk()],
            'given_name' => Sd::hide('John'),
        ]);

        $compact = Presentation::of($sdJwt)
            ->discloseAll()
            ->withKeyBinding(
                JwsSigner::ed25519(sodium_crypto_sign_secretkey($keypair)),
                audience: 'aud',
                nonce: 'n',
                issuedAt: 1700000000,
            );

        // act + assert
        fact(fn () => (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $compact,
            self::issuerKey(),
            KeyBinding::required(audience: 'aud', nonce: 'n'),
        ))->throws(KeyBindingVerificationFailed::class, 'does not match the Holder key');
    }

    public function testWrongKbTypIsRejected(): void
    {
        // arrange: hand-build a KB-JWT with the wrong "typ" header
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'cnf' => ['jwk' => self::holderJwk()],
            'given_name' => Sd::hide('John'),
        ]);

        $sdJwtCompact = Presentation::of($sdJwt)->discloseAll()->toCompact();
        $kbJwt = self::holderSigner()->sign(
            payload: [
                'nonce' => 'n',
                'aud' => 'aud',
                'iat' => 1700000000,
                'sd_hash' => HashAlgorithm::digest('sha-256', $sdJwtCompact),
            ],
            header: ['typ' => 'JWT'],
        );

        // act + assert
        fact(fn () => (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $sdJwtCompact . $kbJwt,
            self::issuerKey(),
            KeyBinding::required(audience: 'aud', nonce: 'n'),
        ))->throws(KeyBindingVerificationFailed::class, 'kb+jwt');
    }

    private function verifier(): SdJwtVerifier
    {
        return new SdJwtVerifier(clock: self::RFC_CLOCK);
    }
}
