<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(SdJwtIssuer::class)]
#[CoversClass(Sd::class)]
final class SdJwtIssuerTest extends SdJwtTestCase
{
    public function testHiddenClaimsBecomeDisclosuresAndDigests(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'sub' => 'user_42',
            'given_name' => Sd::hide('John'),
            'family_name' => Sd::hide('Doe'),
        ]);

        $payload = $sdJwt->payload();

        self::assertCount(2, $sdJwt->disclosures);
        self::assertSame('user_42', $payload->sub);
        self::assertSame('sha-256', $payload->_sd_alg);
        self::assertObjectNotHasProperty('given_name', $payload);

        $digests = array_map(static fn ($d) => $d->digest(), $sdJwt->disclosures);
        sort($digests, SORT_STRING);
        self::assertSame($digests, $payload->_sd);
    }

    public function testSdArrayIsSortedToHideTheOriginalClaimOrder(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        $sdJwt = $issuer->issue([
            'zz' => Sd::hide(1),
            'aa' => Sd::hide(2),
            'mm' => Sd::hide(3),
        ]);

        $sd = $sdJwt->payload()->_sd;
        $sorted = $sd;
        sort($sorted, SORT_STRING);

        self::assertSame($sorted, $sd);
    }

    public function testArrayElementsAndDecoys(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        $sdJwt = $issuer->issue([
            'nationalities' => [Sd::hide('US'), 'DE', Sd::decoy()],
            'padding' => Sd::decoy(),
        ]);

        $payload = $sdJwt->payload();

        // Only the US element has a Disclosure; both decoys are bare digests.
        self::assertCount(1, $sdJwt->disclosures);
        self::assertSame('US', $sdJwt->disclosures[0]->value);
        self::assertTrue($sdJwt->disclosures[0]->isArrayElement());

        self::assertCount(3, $payload->nationalities);
        self::assertSame('DE', $payload->nationalities[1]);
        self::assertObjectHasProperty('...', $payload->nationalities[0]);
        self::assertObjectHasProperty('...', $payload->nationalities[2]);
        self::assertCount(1, $payload->_sd);
    }

    public function testRecursiveDisclosures(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        $sdJwt = $issuer->issue([
            'address' => Sd::hide([
                'street_address' => Sd::hide('123 Main St'),
                'country' => 'US',
            ]),
        ]);

        self::assertCount(2, $sdJwt->disclosures);

        // The inner Disclosure is created first; the outer one embeds its digest.
        [$inner, $outer] = $sdJwt->disclosures;
        self::assertSame('street_address', $inner->claimName);
        self::assertSame('address', $outer->claimName);
        self::assertContains($inner->digest(), $outer->value->_sd);
    }

    public function testWithoutMarkersNothingIsDisclosed(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner());
        $sdJwt = $issuer->issue(['iss' => 'https://issuer.example.com']);
        $payload = $sdJwt->payload();

        self::assertSame([], $sdJwt->disclosures);
        self::assertObjectNotHasProperty('_sd', $payload);
        self::assertObjectNotHasProperty('_sd_alg', $payload);
    }

    public function testIssuedSdJwtVerifiesBackToTheOriginalClaims(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'given_name' => Sd::hide('John'),
            'address' => Sd::hide(['street_address' => Sd::hide('123 Main St'), 'country' => 'US']),
            'nationalities' => [Sd::hide('US'), Sd::hide('DE')],
        ]);

        $claims = (new SdJwtVerifier)->verify($sdJwt->toCompact(), self::issuerKey())->claims();

        self::assertSame('John', $claims['given_name']);
        // Disclosed claims are inserted after plaintext ones, so compare without order.
        self::assertEquals(['street_address' => '123 Main St', 'country' => 'US'], $claims['address']);
        self::assertSame(['US', 'DE'], $claims['nationalities']);
    }

    public function testCustomHashAlgorithm(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner(), hashAlgorithm: 'sha-384', saltGenerator: self::salts());
        $sdJwt = $issuer->issue(['a' => Sd::hide(1)]);

        self::assertSame('sha-384', $sdJwt->payload()->_sd_alg);
        self::assertSame(
            1,
            (new SdJwtVerifier)->verify($sdJwt->toCompact(), self::issuerKey())->claims()['a'],
        );
    }

    public function testUnsupportedHashAlgorithmIsRejected(): void
    {
        $this->expectException(InvalidSdJwtException::class);

        new SdJwtIssuer(self::issuerSigner(), hashAlgorithm: 'md5');
    }

    public function testReservedClaimNamesAreRejected(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner());

        $this->expectException(InvalidSdJwtException::class);

        $issuer->issue(['_sd' => ['x']]);
    }

    public function testListClaimsAreRejected(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner());

        $this->expectException(InvalidSdJwtException::class);

        $issuer->issue(['a', 'b']);
    }

    public function testDoubleHidingIsRejected(): void
    {
        $issuer = new SdJwtIssuer(self::issuerSigner());

        $this->expectException(InvalidSdJwtException::class);

        $issuer->issue(['a' => Sd::hide(Sd::hide(1))]);
    }
}
