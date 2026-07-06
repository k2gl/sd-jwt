<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use stdClass;

/**
 * A compact JWS split into its three base64url parts, with lazily decoded
 * header and payload.
 *
 * @internal
 */
final class JwtParts
{
    private function __construct(
        public readonly string $compact,
        public readonly string $encodedHeader,
        public readonly string $encodedPayload,
        public readonly string $encodedSignature,
    ) {}

    public static function parse(string $compact): self
    {
        $parts = explode('.', $compact);

        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new InvalidSdJwtException('Malformed JWT: expected three dot-separated parts.');
        }

        return new self($compact, $parts[0], $parts[1], $parts[2]);
    }

    public function header(): stdClass
    {
        return Json::decodeObject(Base64Url::decode($this->encodedHeader));
    }

    public function payload(): stdClass
    {
        return Json::decodeObject(Base64Url::decode($this->encodedPayload));
    }

    public function signature(): string
    {
        return Base64Url::decode($this->encodedSignature);
    }

    /** The bytes the signature is computed over. */
    public function signingInput(): string
    {
        return $this->encodedHeader . '.' . $this->encodedPayload;
    }
}
