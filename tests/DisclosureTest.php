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

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Disclosure::class)]
final class DisclosureTest extends SdJwtTestCase
{
    /** RFC 9901 Section 4.2.1: the family_name example Disclosure. */
    private const FAMILY_NAME = 'WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0';

    /** RFC 9901 Section 4.2.1: the family_name example Disclosure. */
    public function testParsesTheRfcPropertyDisclosure(): void
    {
        // act
        $disclosure = Disclosure::fromEncoded(self::FAMILY_NAME);

        // assert
        fact($disclosure->salt)->is('_26bc4LT-ac6q2KI6cBW5es');
        fact($disclosure->claimName)->is('family_name');
        fact($disclosure->value)->is('Möbius');
        fact($disclosure->isArrayElement())->false();
    }

    /** RFC 9901 Section 4.2.3: digest over the encoded form. */
    public function testComputesTheRfcDigest(): void
    {
        // act + assert
        fact(Disclosure::fromEncoded(self::FAMILY_NAME)->digest())
            ->is('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0');
    }

    /** RFC 9901 Sections 4.2.2 and 4.2.4.2: the nationalities array element. */
    public function testParsesTheRfcArrayElementDisclosure(): void
    {
        // act
        $disclosure = Disclosure::fromEncoded('WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0');

        // assert
        fact($disclosure->salt)->is('lklxF5jMYlGTPUovMNIvCA');
        fact($disclosure->claimName)->null();
        fact($disclosure->value)->is('FR');
        fact($disclosure->isArrayElement())->true();
        fact($disclosure->digest())->is('w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs');
    }

    /**
     * RFC 9901 Section 4.2.1: the same logical content in different JSON
     * spellings stays byte-authoritative — same value, different digests.
     */
    #[DataProvider('encodingVariants')]
    public function testEncodingVariantsKeepTheirOwnDigest(string $encoded): void
    {
        // act
        $disclosure = Disclosure::fromEncoded($encoded);

        // assert: the value decodes the same
        fact($disclosure->claimName)->is('family_name');
        fact($disclosure->value)->is('Möbius');

        // assert: but the encoded bytes — and thus the digest — differ from the canonical one
        fact($disclosure->digest())->not('X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0');
        fact($disclosure->encoded)->is($encoded);
    }

    public function testCreatedPropertyDisclosureRoundTrips(): void
    {
        // act
        $created = Disclosure::forProperty(salt: 's-1', claimName: 'email', value: 'a@example.com');
        $parsed = Disclosure::fromEncoded($created->encoded);

        // assert
        fact($parsed->claimName)->is('email');
        fact($parsed->value)->is('a@example.com');
        fact($parsed->digest())->is($created->digest());
    }

    public function testCreatedArrayElementNormalizesObjects(): void
    {
        // act
        $created = Disclosure::forArrayElement(salt: 's-1', value: ['country' => 'US']);

        // assert
        fact($created->value)->instanceOf(stdClass::class);
        fact($created->value->country)->is('US');
    }

    #[DataProvider('reservedNames')]
    public function testRejectsReservedClaimNames(string $name): void
    {
        // act + assert
        fact(static fn () => Disclosure::forProperty(salt: 's-1', claimName: $name, value: 1))
            ->throws(InvalidSdJwtException::class);
    }

    #[DataProvider('malformed')]
    public function testRejectsMalformedDisclosures(string $json): void
    {
        // act + assert
        fact(static fn () => Disclosure::fromEncoded(Base64Url::encode($json)))
            ->throws(InvalidSdJwtException::class);
    }

    public function testRejectsInvalidBase64Url(): void
    {
        // act + assert
        fact(static fn () => Disclosure::fromEncoded('not+base64url/'))
            ->throws(InvalidSdJwtException::class);
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function reservedNames(): iterable
    {
        yield 'sd' => ['_sd'];

        yield 'ellipsis' => ['...'];
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
}
