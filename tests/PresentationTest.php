<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Exception\SelectionException;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(Presentation::class)]
final class PresentationTest extends SdJwtTestCase
{
    public function testExposesTheFullyDisclosedViewAndPaths(): void
    {
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));
        $claims = $presentation->claims();

        self::assertSame('John', $claims['given_name']);
        self::assertSame(['US', 'DE'], $claims['nationalities']);

        $paths = $presentation->disclosablePaths();

        foreach (['/given_name', '/family_name', '/email', '/address', '/nationalities/0', '/nationalities/1'] as $path) {
            self::assertContains($path, $paths);
        }
    }

    public function testSelectionKeepsOnlyTheChosenDisclosures(): void
    {
        $compact = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'))
            ->disclose('/family_name', '/nationalities/0')
            ->toCompact();

        $verified = (new SdJwtVerifier(clock: 1700000000))->verifyPresentation(
            $compact,
            self::rfcIssuerKey(),
            KeyBinding::notRequired(),
        );
        $claims = $verified->claims();

        self::assertSame('Doe', $claims['family_name']);
        self::assertSame(['US'], $claims['nationalities']);
        self::assertArrayNotHasKey('given_name', $claims);
        self::assertArrayNotHasKey('email', $claims);
    }

    public function testNestedSelectionIncludesParentDisclosures(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'address' => Sd::hide([
                'street_address' => Sd::hide('123 Main St'),
                'locality' => Sd::hide('Anytown'),
            ]),
        ]);

        $compact = Presentation::of($sdJwt)->disclose('/address/street_address')->toCompact();

        $claims = (new SdJwtVerifier)
            ->verifyPresentation($compact, self::issuerKey(), KeyBinding::notRequired())
            ->claims();

        // The parent "address" Disclosure came along; the sibling stayed hidden.
        self::assertSame(['street_address' => '123 Main St'], $claims['address']);
    }

    public function testDiscloseAllReleasesEverything(): void
    {
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));

        self::assertCount(10, $presentation->discloseAll()->toSdJwt()->disclosures);
    }

    public function testNothingIsDisclosedByDefault(): void
    {
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));

        self::assertSame([], $presentation->toSdJwt()->disclosures);
    }

    public function testUnknownPathIsRejected(): void
    {
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));

        $this->expectException(SelectionException::class);

        $presentation->disclose('/nope');
    }

    public function testRejectsAnSdJwtKb(): void
    {
        $this->expectException(InvalidSdJwtException::class);

        Presentation::of(self::fixture('rfc9901/presentation-sd-jwt-kb.txt'));
    }

    public function testKeyBindingProducesAVerifiablePresentation(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'cnf' => ['jwk' => self::holderJwk()],
            'given_name' => Sd::hide('John'),
        ]);

        $compact = Presentation::of($sdJwt)
            ->disclose('/given_name')
            ->withKeyBinding(
                self::holderSigner(),
                audience: 'https://verifier.example.org',
                nonce: 'n-123',
                issuedAt: 1700000000,
            );

        $verified = (new SdJwtVerifier(clock: 1700000060))->verifyPresentation(
            $compact,
            self::issuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: 'n-123'),
        );

        self::assertSame('John', $verified->claims()['given_name']);

        $kb = $verified->keyBindingPayload();
        self::assertNotNull($kb);

        $sdJwtPart = SdJwt::parse($compact)->withoutKeyBinding()->toCompact();
        self::assertSame(HashAlgorithm::digest('sha-256', $sdJwtPart), $kb->sd_hash);
    }
}
