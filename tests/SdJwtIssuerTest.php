<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SdJwtIssuer::class)]
#[CoversClass(Sd::class)]
final class SdJwtIssuerTest extends SdJwtTestCase
{
    public function testHiddenClaimsBecomeDisclosuresAndDigests(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        // act
        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'sub' => 'user_42',
            'given_name' => Sd::hide('John'),
            'family_name' => Sd::hide('Doe'),
        ]);
        $payload = $sdJwt->payload();

        // assert: hidden claims left the payload, plaintext ones stayed
        fact($sdJwt->disclosures)->count(2);
        fact($payload->sub)->is('user_42');
        fact($payload->_sd_alg)->is('sha-256');
        fact($payload)->notHasProperty('given_name');

        // assert: the _sd array holds exactly the (sorted) Disclosure digests
        $digests = array_map(static fn ($d) => $d->digest(), $sdJwt->disclosures);
        sort($digests, SORT_STRING);
        fact($payload->_sd)->is($digests);
    }

    public function testSdArrayIsSortedToHideTheOriginalClaimOrder(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        // act
        $sdJwt = $issuer->issue([
            'zz' => Sd::hide(1),
            'aa' => Sd::hide(2),
            'mm' => Sd::hide(3),
        ]);

        // assert
        $sd = $sdJwt->payload()->_sd;
        $sorted = $sd;
        sort($sorted, SORT_STRING);
        fact($sd)->is($sorted);
    }

    public function testArrayElementsAndDecoys(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        // act
        $sdJwt = $issuer->issue([
            'nationalities' => [Sd::hide('US'), 'DE', Sd::decoy()],
            'padding' => Sd::decoy(),
        ]);
        $payload = $sdJwt->payload();

        // assert: only the US element has a Disclosure; both decoys are bare digests
        fact($sdJwt->disclosures)->count(1);
        fact($sdJwt->disclosures[0]->value)->is('US');
        fact($sdJwt->disclosures[0]->isArrayElement())->true();

        // assert: the array keeps its shape, plaintext element in place, hidden ones as {"...": digest}
        fact($payload->nationalities)->count(3);
        fact($payload->nationalities[1])->is('DE');
        fact($payload->nationalities[0])->hasProperty('...');
        fact($payload->nationalities[2])->hasProperty('...');
        fact($payload->_sd)->count(1);
    }

    public function testRecursiveDisclosures(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        // act
        $sdJwt = $issuer->issue([
            'address' => Sd::hide([
                'street_address' => Sd::hide('123 Main St'),
                'country' => 'US',
            ]),
        ]);

        // assert: the inner Disclosure is created first; the outer one embeds its digest
        fact($sdJwt->disclosures)->count(2);
        [$inner, $outer] = $sdJwt->disclosures;
        fact($inner->claimName)->is('street_address');
        fact($outer->claimName)->is('address');
        fact($outer->value->_sd)->contains($inner->digest());
    }

    public function testCustomHashAlgorithm(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), hashAlgorithm: 'sha-384', saltGenerator: self::salts());

        // act
        $sdJwt = $issuer->issue(['a' => Sd::hide(1)]);

        // assert
        fact($sdJwt->payload()->_sd_alg)->is('sha-384');
        fact((new SdJwtVerifier)->verify($sdJwt->toCompact(), self::issuerKey())->claims()['a'])->is(1);
    }

    public function testWithoutMarkersNothingIsDisclosed(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner());

        // act
        $sdJwt = $issuer->issue(['iss' => 'https://issuer.example.com']);
        $payload = $sdJwt->payload();

        // assert
        fact($sdJwt->disclosures)->is([]);
        fact($payload)->notHasProperty('_sd');
        fact($payload)->notHasProperty('_sd_alg');
    }

    public function testIssuedSdJwtVerifiesBackToTheOriginalClaims(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts());

        // act
        $sdJwt = $issuer->issue([
            'iss' => 'https://issuer.example.com',
            'given_name' => Sd::hide('John'),
            'address' => Sd::hide(['street_address' => Sd::hide('123 Main St'), 'country' => 'US']),
            'nationalities' => [Sd::hide('US'), Sd::hide('DE')],
        ]);
        $claims = (new SdJwtVerifier)->verify($sdJwt->toCompact(), self::issuerKey())->claims();

        // assert
        fact($claims['given_name'])->is('John');
        // Disclosed claims are inserted after plaintext ones, so key order differs — compare by value.
        fact($claims['address'])->equals(['street_address' => '123 Main St', 'country' => 'US']);
        fact($claims['nationalities'])->is(['US', 'DE']);
    }

    public function testUnsupportedHashAlgorithmIsRejected(): void
    {
        // act + assert
        fact(static fn () => new SdJwtIssuer(self::issuerSigner(), hashAlgorithm: 'md5'))
            ->throws(InvalidSdJwtException::class);
    }

    public function testReservedClaimNamesAreRejected(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['_sd' => ['x']]))->throws(InvalidSdJwtException::class);
    }

    public function testListClaimsAreRejected(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['a', 'b']))->throws(InvalidSdJwtException::class);
    }

    public function testDoubleHidingIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::issuerSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['a' => Sd::hide(Sd::hide(1))]))
            ->throws(InvalidSdJwtException::class);
    }
}
