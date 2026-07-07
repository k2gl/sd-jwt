<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SdJwt::class)]
final class SdJwtTest extends SdJwtTestCase
{
    public function testParsesTheRfcIssuanceSdJwt(): void
    {
        // arrange
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt');

        // act
        $sdJwt = SdJwt::parse($compact);

        // assert
        fact($sdJwt->disclosures)->count(10);
        fact($sdJwt->hasKeyBinding())->false();
        fact($sdJwt->header()->typ)->is('example+sd-jwt');
        fact($sdJwt->payload()->iss)->is('https://issuer.example.com');
        fact($sdJwt->toCompact())->is($compact);
    }

    public function testParsesTheRfcPresentationSdJwtKb(): void
    {
        // arrange
        $compact = self::fixture('rfc9901/presentation-sd-jwt-kb.txt');

        // act
        $sdJwt = SdJwt::parse($compact);

        // assert
        fact($sdJwt->disclosures)->count(4);
        fact($sdJwt->hasKeyBinding())->true();
        fact($sdJwt->toCompact())->is($compact);
    }

    public function testParsesAnSdJwtWithoutDisclosures(): void
    {
        // arrange
        $jwt = self::fixture('rfc9901/issuer-signed-jwt.txt');

        // act
        $sdJwt = SdJwt::parse($jwt . '~');

        // assert
        fact($sdJwt->disclosures)->is([]);
        fact($sdJwt->hasKeyBinding())->false();
    }

    public function testWithoutKeyBindingDropsTheKbJwtAndRestoresTheTrailingTilde(): void
    {
        // arrange
        $sdJwt = SdJwt::parse(self::fixture('rfc9901/presentation-sd-jwt-kb.txt'));

        // act
        $stripped = $sdJwt->withoutKeyBinding();

        // assert
        fact($stripped->hasKeyBinding())->false();
        fact($stripped->toCompact())->endsWith('~');
        fact($stripped->disclosures)->count(4);
    }

    #[DataProvider('malformed')]
    public function testRejectsMalformedInput(string $compact): void
    {
        // act + assert
        fact(static fn () => SdJwt::parse($compact))->throws(InvalidSdJwtException::class);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformed(): iterable
    {
        yield 'no tilde' => ['eyJh.eyJi.c2ln'];

        yield 'empty string' => [''];

        yield 'empty disclosure' => ['eyJh.eyJi.c2ln~~WyJz  Il0~'];

        yield 'jwt with two parts' => ['eyJh.eyJi~'];

        yield 'jwt with empty signature' => ['eyJh.eyJi.~'];
    }
}
