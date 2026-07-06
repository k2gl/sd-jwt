<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use JsonException;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use stdClass;

/**
 * JSON helpers that keep the object/array distinction: JSON objects decode to
 * {@see stdClass}, JSON arrays to PHP lists. SD-JWT processing depends on that
 * distinction (an empty object must stay `{}`, not become `[]`).
 *
 * @internal
 */
final class Json
{
    public static function decode(string $json): mixed
    {
        try {
            return json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidSdJwtException('Invalid JSON: ' . $e->getMessage(), previous: $e);
        }
    }

    public static function decodeObject(string $json): stdClass
    {
        $decoded = self::decode($json);

        if (! $decoded instanceof stdClass) {
            throw new InvalidSdJwtException('Expected a JSON object.');
        }

        return $decoded;
    }

    /**
     * Compact encoding with unescaped slashes and Unicode, matching common
     * JOSE practice. Used for everything this package emits (JWT headers and
     * payloads, Disclosures).
     */
    public static function encode(mixed $value): string
    {
        try {
            return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (JsonException $e) {
            throw new InvalidSdJwtException('Unable to encode JSON: ' . $e->getMessage(), previous: $e);
        }
    }
}
