<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use K2gl\SdJwt\Exception\InvalidSdJwtException;

/**
 * Base64url without padding (RFC 4648 Section 5), as used throughout JOSE.
 *
 * @internal
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode(string $encoded): string
    {
        if ($encoded === '' || preg_match('/^[A-Za-z0-9_-]+$/', $encoded) !== 1) {
            throw new InvalidSdJwtException('Invalid base64url data.');
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        if ($decoded === false) {
            throw new InvalidSdJwtException('Invalid base64url data.');
        }

        return $decoded;
    }
}
