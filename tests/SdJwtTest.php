<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(SdJwt::class)]
final class SdJwtTest extends SdJwtTestCase
{
    public function testParsesTheRfcIssuanceSdJwt(): void
    {
        $compact = self::fixture('rfc9901/issuance-sd-jwt.txt');
        $sdJwt = SdJwt::parse($compact);

        self::assertCount(10, $sdJwt->disclosures);
        self::assertFalse($sdJwt->hasKeyBinding());
        self::assertSame('example+sd-jwt', $sdJwt->header()->typ);
        self::assertSame('https://issuer.example.com', $sdJwt->payload()->iss);
        self::assertSame($compact, $sdJwt->toCompact());
    }

    public function testParsesTheRfcPresentationSdJwtKb(): void
    {
        $compact = self::fixture('rfc9901/presentation-sd-jwt-kb.txt');
        $sdJwt = SdJwt::parse($compact);

        self::assertCount(4, $sdJwt->disclosures);
        self::assertTrue($sdJwt->hasKeyBinding());
        self::assertSame($compact, $sdJwt->toCompact());
    }

    public function testWithoutKeyBindingDropsTheKbJwtAndRestoresTheTrailingTilde(): void
    {
        $sdJwt = SdJwt::parse(self::fixture('rfc9901/presentation-sd-jwt-kb.txt'));
        $stripped = $sdJwt->withoutKeyBinding();

        self::assertFalse($stripped->hasKeyBinding());
        self::assertStringEndsWith('~', $stripped->toCompact());
        self::assertCount(4, $stripped->disclosures);
    }

    public function testParsesAnSdJwtWithoutDisclosures(): void
    {
        $jwt = self::fixture('rfc9901/issuer-signed-jwt.txt');
        $sdJwt = SdJwt::parse($jwt . '~');

        self::assertSame([], $sdJwt->disclosures);
        self::assertFalse($sdJwt->hasKeyBinding());
    }

    #[DataProvider('malformed')]
    public function testRejectsMalformedInput(string $compact): void
    {
        $this->expectException(InvalidSdJwtException::class);

        SdJwt::parse($compact);
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
