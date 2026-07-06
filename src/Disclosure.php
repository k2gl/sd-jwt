<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\Internal\Json;

/**
 * A single Disclosure (RFC 9901 Section 4.2): the base64url-encoded JSON
 * array `[salt, claim name, value]` for an object property, or
 * `[salt, value]` for an array element.
 *
 * The encoded form is authoritative — digests are computed over it byte for
 * byte, so it is preserved exactly as parsed or created.
 */
final class Disclosure
{
    private function __construct(
        public readonly string $encoded,
        public readonly string $salt,
        public readonly ?string $claimName,
        public readonly mixed $value,
    ) {}

    /**
     * Parse a Disclosure from its base64url-encoded form. JSON objects inside
     * the value decode to stdClass to keep the object/array distinction.
     */
    public static function fromEncoded(string $encoded): self
    {
        $decoded = Json::decode(Base64Url::decode($encoded));

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            throw new InvalidSdJwtException('A Disclosure must decode to a JSON array.');
        }

        $count = count($decoded);

        if ($count !== 2 && $count !== 3) {
            throw new InvalidSdJwtException('A Disclosure must be a JSON array of two or three elements.');
        }

        if (! is_string($decoded[0])) {
            throw new InvalidSdJwtException('The Disclosure salt must be a string.');
        }

        if ($count === 3) {
            if (! is_string($decoded[1])) {
                throw new InvalidSdJwtException('The Disclosure claim name must be a string.');
            }

            return new self($encoded, $decoded[0], $decoded[1], $decoded[2]);
        }

        return new self($encoded, $decoded[0], null, $decoded[1]);
    }

    /** Create a Disclosure for an object property. */
    public static function forProperty(string $salt, string $claimName, mixed $value): self
    {
        if ($claimName === '_sd' || $claimName === '...') {
            throw new InvalidSdJwtException(sprintf('"%s" cannot be used as a Disclosure claim name.', $claimName));
        }

        $encoded = Base64Url::encode(Json::encode([$salt, $claimName, $value]));

        return new self(
            encoded: $encoded,
            salt: $salt,
            claimName: $claimName,
            value: self::normalized($value),
        );
    }

    /** Create a Disclosure for an array element. */
    public static function forArrayElement(string $salt, mixed $value): self
    {
        $encoded = Base64Url::encode(Json::encode([$salt, $value]));

        return new self(
            encoded: $encoded,
            salt: $salt,
            claimName: null,
            value: self::normalized($value),
        );
    }

    /**
     * Values pass through a JSON round trip so that {@see $value} always uses
     * the decoded shape (objects as stdClass, arrays as lists), no matter how
     * the caller spelled it.
     */
    private static function normalized(mixed $value): mixed
    {
        return Json::decode(Json::encode($value));
    }

    /** Whether this Disclosure hides an array element (two-element form). */
    public function isArrayElement(): bool
    {
        return $this->claimName === null;
    }

    /**
     * The base64url-encoded digest of this Disclosure (RFC 9901
     * Section 4.2.3), computed over the encoded form.
     */
    public function digest(string $hashAlgorithm = HashAlgorithm::DEFAULT): string
    {
        return HashAlgorithm::digest($hashAlgorithm, $this->encoded);
    }
}
