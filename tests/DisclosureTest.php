<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Disclosure;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use stdClass;

#[CoversClass(Disclosure::class)]
final class DisclosureTest extends SdJwtTestCase
{
    /** RFC 9901 Section 4.2.1: the family_name example Disclosure. */
    private const FAMILY_NAME = 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0';

    public function testParsesTheRfcPropertyDisclosure(): void
    {
        $disclosure = Disclosure::fromEncoded(self::FAMILY_NAME);

        self::assertSame('_26bc4LT-ac6q2KI6cBW5es', $disclosure->salt);
        self::assertSame('family_name', $disclosure->claimName);
        self::assertSame('Möbius', $disclosure->value);
        self::assertFalse($disclosure->isArrayElement());
    }

    /** RFC 9901 Section 4.2.3: digest over the encoded form. */
    public function testComputesTheRfcDigest(): void
    {
        self::assertSame(
            'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0',
            Disclosure::fromEncoded(self::FAMILY_NAME)->digest(),
        );
    }

    /**
     * RFC 9901 Section 4.2.1: the same logical content in different JSON
     * spellings stays byte-authoritative — same value, different digests.
     */
    #[DataProvider('encodingVariants')]
    public function testEncodingVariantsKeepTheirOwnDigest(string $encoded): void
    {
        $disclosure = Disclosure::fromEncoded($encoded);

        self::assertSame('family_name', $disclosure->claimName);
        self::assertSame('Möbius', $disclosure->value);
        self::assertNotSame('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0', $disclosure->digest());
        self::assertSame($encoded, $disclosure->encoded);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function encodingVariants(): iterable
    {
        yield 'escaped umlaut' => ['WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd'];

        yield 'no whitespace' => ['WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd'];

        yield 'newlines' => ['WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ'];
    }

    /** RFC 9901 Sections 4.2.2 and 4.2.4.2: the nationalities array element. */
    public function testParsesTheRfcArrayElementDisclosure(): void
    {
        $disclosure = Disclosure::fromEncoded('WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0');

        self::assertSame('lklxF5jMYlGTPUovMNIvCA', $disclosure->salt);
        self::assertNull($disclosure->claimName);
        self::assertSame('FR', $disclosure->value);
        self::assertTrue($disclosure->isArrayElement());
        self::assertSame('w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs', $disclosure->digest());
    }

    public function testCreatedPropertyDisclosureRoundTrips(): void
    {
        $created = Disclosure::forProperty(salt: 's-1', claimName: 'email', value: 'a@example.com');
        $parsed = Disclosure::fromEncoded($created->encoded);

        self::assertSame('email', $parsed->claimName);
        self::assertSame('a@example.com', $parsed->value);
        self::assertSame($created->digest(), $parsed->digest());
    }

    public function testCreatedArrayElementNormalizesObjects(): void
    {
        $created = Disclosure::forArrayElement(salt: 's-1', value: ['country' => 'US']);

        self::assertInstanceOf(stdClass::class, $created->value);
        self::assertSame('US', $created->value->country);
    }

    #[DataProvider('reservedNames')]
    public function testRejectsReservedClaimNames(string $name): void
    {
        $this->expectException(InvalidSdJwtException::class);

        Disclosure::forProperty(salt: 's-1', claimName: $name, value: 1);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function reservedNames(): iterable
    {
        yield 'sd' => ['_sd'];

        yield 'ellipsis' => ['...'];
    }

    #[DataProvider('malformed')]
    public function testRejectsMalformedDisclosures(string $json): void
    {
        $this->expectException(InvalidSdJwtException::class);

        Disclosure::fromEncoded(Base64Url::encode($json));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformed(): iterable
    {
        yield 'not an array' => ['{"salt":"x"}'];

        yield 'one element' => ['["salt"]'];

        yield 'four elements' => ['["salt","name","value","extra"]'];

        yield 'non-string salt' => ['[1,"name","value"]'];

        yield 'non-string claim name' => ['["salt",2,"value"]'];

        yield 'not JSON' => ['nope'];
    }

    public function testRejectsInvalidBase64Url(): void
    {
        $this->expectException(InvalidSdJwtException::class);

        Disclosure::fromEncoded('not+base64url/');
    }
}
