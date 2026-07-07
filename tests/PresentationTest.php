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

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Presentation::class)]
final class PresentationTest extends SdJwtTestCase
{
    public function testExposesTheFullyDisclosedViewAndPaths(): void
    {
        // act
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));
        $claims = $presentation->claims();

        // assert: the fully disclosed view
        fact($claims['given_name'])->is('John');
        fact($claims['nationalities'])->is(['US', 'DE']);

        // assert: every selectively disclosable claim is offered as a path
        $paths = $presentation->disclosablePaths();

        foreach (['/given_name', '/family_name', '/email', '/address', '/nationalities/0', '/nationalities/1'] as $path) {
            fact($paths)->contains($path);
        }
    }

    public function testNothingIsDisclosedByDefault(): void
    {
        // act
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));

        // assert
        fact($presentation->toSdJwt()->disclosures)->is([]);
    }

    public function testDiscloseAllReleasesEverything(): void
    {
        // act
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));

        // assert
        fact($presentation->discloseAll()->toSdJwt()->disclosures)->count(10);
    }

    public function testSelectionKeepsOnlyTheChosenDisclosures(): void
    {
        // act
        $compact = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'))
            ->disclose('/family_name', '/nationalities/0')
            ->toCompact();
        $claims = (new SdJwtVerifier(clock: 1700000000))
            ->verifyPresentation($compact, self::rfcIssuerKey(), KeyBinding::notRequired())
            ->claims();

        // assert: only the chosen claims survive
        fact($claims['family_name'])->is('Doe');
        fact($claims['nationalities'])->is(['US']);
        fact($claims)->arrayNotHasKey('given_name');
        fact($claims)->arrayNotHasKey('email');
    }

    public function testNestedSelectionIncludesParentDisclosures(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'address' => Sd::hide([
                'street_address' => Sd::hide('123 Main St'),
                'locality' => Sd::hide('Anytown'),
            ]),
        ]);

        // act
        $compact = Presentation::of($sdJwt)->disclose('/address/street_address')->toCompact();
        $claims = (new SdJwtVerifier)
            ->verifyPresentation($compact, self::issuerKey(), KeyBinding::notRequired())
            ->claims();

        // assert: the parent "address" Disclosure came along; the sibling stayed hidden
        fact($claims['address'])->is(['street_address' => '123 Main St']);
    }

    public function testKeyBindingProducesAVerifiablePresentation(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());
        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'cnf' => ['jwk' => self::holderJwk()],
            'given_name' => Sd::hide('John'),
        ]);

        // act
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

        // assert: the disclosed claim verifies
        fact($verified->claims()['given_name'])->is('John');

        // assert: the KB-JWT binds to exactly this presentation via sd_hash
        $kb = $verified->keyBindingPayload();
        fact($kb)->notNull();
        $sdJwtPart = SdJwt::parse($compact)->withoutKeyBinding()->toCompact();
        fact($kb->sd_hash)->is(HashAlgorithm::digest('sha-256', $sdJwtPart));
    }

    public function testUnknownPathIsRejected(): void
    {
        // arrange
        $presentation = Presentation::of(self::fixture('rfc9901/issuance-sd-jwt.txt'));

        // act + assert
        fact(fn () => $presentation->disclose('/nope'))->throws(SelectionException::class);
    }

    public function testRejectsAnSdJwtKb(): void
    {
        // act + assert
        fact(static fn () => Presentation::of(self::fixture('rfc9901/presentation-sd-jwt-kb.txt')))
            ->throws(InvalidSdJwtException::class);
    }
}
