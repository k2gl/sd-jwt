<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use K2gl\SdJwt\Exception\InvalidSdJwtException;

/**
 * Maps the IANA "Named Information Hash Algorithm" identifiers used by the
 * `_sd_alg` claim to PHP hash() algorithm names.
 *
 * @internal
 */
final class HashAlgorithm
{
    public const DEFAULT = 'sha-256';

    private const SUPPORTED = [
        'sha-256' => 'sha256',
        'sha-384' => 'sha384',
        'sha-512' => 'sha512',
    ];

    public static function digest(string $ianaName, string $data): string
    {
        return Base64Url::encode(hash(self::phpName($ianaName), $data, true));
    }

    public static function isSupported(string $ianaName): bool
    {
        return isset(self::SUPPORTED[$ianaName]);
    }

    private static function phpName(string $ianaName): string
    {
        $phpName = self::SUPPORTED[$ianaName] ?? null;

        if ($phpName === null) {
            throw new InvalidSdJwtException(sprintf('Unsupported hash algorithm "%s".', $ianaName));
        }

        return $phpName;
    }
}
