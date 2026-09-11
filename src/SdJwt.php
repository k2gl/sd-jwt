<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Internal\JwtParts;
use K2gl\SdJwt\Internal\JwsJson;
use stdClass;

/**
 * An SD-JWT or SD-JWT+KB as a whole: the Issuer-signed JWT, its Disclosures,
 * and optionally a Key Binding JWT (RFC 9901 Section 4). Parses and emits
 * both the compact serialization (Section 4.1) and the JWS JSON serialization
 * (Section 8).
 */
final class SdJwt
{
    /**
     * @param list<Disclosure> $disclosures
     * @param array<string, mixed> $unprotectedHeader members of the JWS JSON
     *     unprotected header other than `disclosures` and `kb_jwt` (e.g. `kid`)
     * @param list<array{protected: string, header: array<string, mixed>, signature: string}> $additionalSignatures
     *     further signatures of a General JSON serialization; they are not verified
     */
    private function __construct(
        public readonly string $issuerSignedJwt,
        public readonly array $disclosures,
        public readonly ?string $keyBindingJwt,
        public readonly array $unprotectedHeader = [],
        public readonly array $additionalSignatures = [],
    ) {
        JwtParts::parse($issuerSignedJwt);
    }

    /**
     * Parse either serialization: compact (`<JWT>~<Disclosure>~...~[<KB-JWT>]`)
     * or JWS JSON (a JSON object, Section 8).
     */
    public static function parse(string $serialized): self
    {
        if (str_starts_with(ltrim($serialized), '{')) {
            return self::fromJson($serialized);
        }

        $parts = explode('~', $serialized);

        if (count($parts) < 2) {
            throw new InvalidSdJwtException(
                'Malformed SD-JWT: expected <JWT>~<Disclosure 1>~...~<Disclosure N>~[<KB-JWT>].',
            );
        }

        $issuerSignedJwt = array_shift($parts);
        $last = array_pop($parts);
        $keyBindingJwt = $last === '' ? null : $last;
        $disclosures = [];

        foreach ($parts as $encoded) {
            if ($encoded === '') {
                throw new InvalidSdJwtException('Malformed SD-JWT: empty Disclosure.');
            }

            $disclosures[] = Disclosure::fromEncoded($encoded);
        }

        return new self($issuerSignedJwt, $disclosures, $keyBindingJwt);
    }

    /**
     * Parse the JWS JSON serialization (RFC 9901 Section 8), Flattened or
     * General. In the General form the Disclosures and Key Binding JWT live in
     * the first signature's unprotected header; that signature is the one
     * verified, the others are carried along for re-serialization.
     *
     * @param string|array<string, mixed> $json
     */
    public static function fromJson(string|array $json): self
    {
        $parsed = JwsJson::parse($json);

        return new self(
            issuerSignedJwt: $parsed['issuerSignedJwt'],
            disclosures: $parsed['disclosures'],
            keyBindingJwt: $parsed['keyBindingJwt'],
            unprotectedHeader: $parsed['unprotectedHeader'],
            additionalSignatures: $parsed['additionalSignatures'],
        );
    }

    /**
     * @param list<Disclosure> $disclosures
     */
    public static function create(string $issuerSignedJwt, array $disclosures, ?string $keyBindingJwt = null): self
    {
        return new self($issuerSignedJwt, $disclosures, $keyBindingJwt);
    }

    public function hasKeyBinding(): bool
    {
        return $this->keyBindingJwt !== null;
    }

    public function withoutKeyBinding(): self
    {
        return new self(
            issuerSignedJwt: $this->issuerSignedJwt,
            disclosures: $this->disclosures,
            keyBindingJwt: null,
            unprotectedHeader: $this->unprotectedHeader,
            additionalSignatures: $this->additionalSignatures,
        );
    }

    public function header(): stdClass
    {
        return JwtParts::parse($this->issuerSignedJwt)->header();
    }

    public function payload(): stdClass
    {
        return JwtParts::parse($this->issuerSignedJwt)->payload();
    }

    /**
     * The compact serialization. Additional signatures of a General JSON
     * serialization have no place in it and are dropped.
     */
    public function toCompact(): string
    {
        $result = $this->issuerSignedJwt . '~';

        foreach ($this->disclosures as $disclosure) {
            $result .= $disclosure->encoded . '~';
        }

        return $result . ($this->keyBindingJwt ?? '');
    }

    /**
     * The JWS JSON serialization (RFC 9901 Section 8). Flattened by default;
     * General when requested or whenever additional signatures are present.
     */
    public function toJson(?bool $general = null): string
    {
        return JwsJson::encode($this->toJsonArray($general));
    }

    /**
     * @return array<string, mixed>
     */
    public function toJsonArray(?bool $general = null): array
    {
        return JwsJson::build($this, $general ?? $this->additionalSignatures !== []);
    }
}
