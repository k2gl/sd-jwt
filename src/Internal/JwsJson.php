<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use K2gl\SdJwt\Disclosure;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\SdJwt;
use stdClass;

/**
 * The JWS JSON serialization of an SD-JWT (RFC 9901 Section 8): the
 * Flattened (Section 8.2) and General (Section 8.3) forms of RFC 7515
 * Section 7.2, with the `disclosures` and `kb_jwt` unprotected header
 * parameters of Section 8.1.
 *
 * @internal
 */
final class JwsJson
{
    /**
     * @param string|array<string, mixed> $json
     * @return array{
     *     issuerSignedJwt: string,
     *     disclosures: list<Disclosure>,
     *     keyBindingJwt: ?string,
     *     unprotectedHeader: array<string, mixed>,
     *     additionalSignatures: list<array{protected: string, header: array<string, mixed>, signature: string}>,
     * }
     */
    public static function parse(string|array $json): array
    {
        $object = is_string($json) ? self::decodeObject($json) : $json;
        $payload = $object['payload'] ?? null;

        if (! is_string($payload) || $payload === '') {
            throw new InvalidSdJwtException('Malformed JWS JSON: "payload" must be a non-empty string.');
        }

        $signatures = array_key_exists('signatures', $object)
            ? self::generalSignatures($object)
            : [self::signature($object, 'the JWS')];

        [$first, $additional] = [$signatures[0], array_slice($signatures, 1)];

        foreach ($additional as $index => $other) {
            if (isset($other['header']['disclosures']) || isset($other['header']['kb_jwt'])) {
                throw new InvalidSdJwtException(sprintf(
                    'Malformed JWS JSON: "disclosures" and "kb_jwt" belong to the first signature only (found in signature %d).',
                    $index + 2,
                ));
            }
        }

        $header = $first['header'];
        $disclosures = [];

        if (array_key_exists('disclosures', $header)) {
            if (! is_array($header['disclosures']) || ! array_is_list($header['disclosures'])) {
                throw new InvalidSdJwtException('Malformed JWS JSON: "disclosures" must be an array of strings.');
            }

            foreach ($header['disclosures'] as $encoded) {
                if (! is_string($encoded) || $encoded === '') {
                    throw new InvalidSdJwtException('Malformed JWS JSON: "disclosures" must be an array of strings.');
                }

                $disclosures[] = Disclosure::fromEncoded($encoded);
            }
        }

        $keyBindingJwt = $header['kb_jwt'] ?? null;

        if ($keyBindingJwt !== null && (! is_string($keyBindingJwt) || $keyBindingJwt === '')) {
            throw new InvalidSdJwtException('Malformed JWS JSON: "kb_jwt" must be a non-empty string.');
        }

        unset($header['disclosures'], $header['kb_jwt']);

        return [
            'issuerSignedJwt' => $first['protected'] . '.' . $payload . '.' . $first['signature'],
            'disclosures' => $disclosures,
            'keyBindingJwt' => $keyBindingJwt,
            'unprotectedHeader' => $header,
            'additionalSignatures' => $additional,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public static function build(SdJwt $sdJwt, bool $general): array
    {
        $parts = JwtParts::parse($sdJwt->issuerSignedJwt);
        $header = [];

        if ($sdJwt->disclosures !== []) {
            $header['disclosures'] = array_map(static fn (Disclosure $d): string => $d->encoded, $sdJwt->disclosures);
        }

        $header += $sdJwt->unprotectedHeader;

        if ($sdJwt->keyBindingJwt !== null) {
            $header['kb_jwt'] = $sdJwt->keyBindingJwt;
        }

        if (! $general) {
            if ($sdJwt->additionalSignatures !== []) {
                throw new InvalidSdJwtException('An SD-JWT with several signatures needs the General JSON serialization.');
            }

            $flattened = $header === [] ? [] : ['header' => $header];

            return $flattened + [
                'payload' => $parts->encodedPayload,
                'protected' => $parts->encodedHeader,
                'signature' => $parts->encodedSignature,
            ];
        }

        $first = ($header === [] ? [] : ['header' => $header]) + [
            'protected' => $parts->encodedHeader,
            'signature' => $parts->encodedSignature,
        ];
        $others = array_map(
            static fn (array $s): array => ($s['header'] === [] ? [] : ['header' => $s['header']])
                + ['protected' => $s['protected'], 'signature' => $s['signature']],
            $sdJwt->additionalSignatures,
        );

        return ['payload' => $parts->encodedPayload, 'signatures' => [$first, ...$others]];
    }

    /**
     * @param array<string, mixed> $value
     */
    public static function encode(array $value): string
    {
        return Json::encode($value);
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeObject(string $json): array
    {
        $decoded = Json::decode($json);

        if (! $decoded instanceof stdClass) {
            throw new InvalidSdJwtException('Malformed JWS JSON: expected a JSON object.');
        }

        /** @var array<string, mixed> */
        return json_decode(Json::encode($decoded), true);
    }

    /**
     * @param array<string, mixed> $object
     * @return non-empty-list<array{protected: string, header: array<string, mixed>, signature: string}>
     */
    private static function generalSignatures(array $object): array
    {
        $signatures = $object['signatures'];

        if (! is_array($signatures) || ! array_is_list($signatures) || $signatures === []) {
            throw new InvalidSdJwtException('Malformed JWS JSON: "signatures" must be a non-empty array.');
        }

        $result = [];

        foreach ($signatures as $index => $signature) {
            if (! is_array($signature)) {
                throw new InvalidSdJwtException(sprintf('Malformed JWS JSON: signature %d is not an object.', $index + 1));
            }

            /** @var array<string, mixed> $signature */
            $result[] = self::signature($signature, sprintf('signature %d', $index + 1));
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $object
     * @return array{protected: string, header: array<string, mixed>, signature: string}
     */
    private static function signature(array $object, string $what): array
    {
        $protected = $object['protected'] ?? null;
        $signature = $object['signature'] ?? null;
        $header = $object['header'] ?? [];

        if (! is_string($protected) || $protected === '') {
            throw new InvalidSdJwtException(sprintf('Malformed JWS JSON: %s has no "protected" header.', $what));
        }

        if (! is_string($signature) || $signature === '') {
            throw new InvalidSdJwtException(sprintf('Malformed JWS JSON: %s has no "signature".', $what));
        }

        if (! is_array($header) || ($header !== [] && array_is_list($header))) {
            throw new InvalidSdJwtException(sprintf('Malformed JWS JSON: the unprotected "header" of %s must be an object.', $what));
        }

        /** @var array<string, mixed> $header */
        return ['protected' => $protected, 'header' => $header, 'signature' => $signature];
    }
}
