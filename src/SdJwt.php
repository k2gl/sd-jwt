<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Internal\JwtParts;
use stdClass;

/**
 * A parsed SD-JWT or SD-JWT+KB in the compact serialization (RFC 9901
 * Section 4): the Issuer-signed JWT, zero or more Disclosures, and an
 * optional Key Binding JWT.
 *
 * Parsing is purely structural; nothing is verified. Use
 * {@see SdJwtVerifier} to validate and extract the processed payload.
 */
final class SdJwt
{
    /**
     * @param list<Disclosure> $disclosures
     */
    private function __construct(
        public readonly string $issuerSignedJwt,
        public readonly array $disclosures,
        public readonly ?string $keyBindingJwt,
    ) {
        JwtParts::parse($issuerSignedJwt);
    }

    public static function parse(string $compact): self
    {
        $parts = explode('~', $compact);

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
     * @param list<Disclosure> $disclosures
     */
    public static function create(string $issuerSignedJwt, array $disclosures, ?string $keyBindingJwt = null): self
    {
        return new self($issuerSignedJwt, $disclosures, $keyBindingJwt);
    }

    /** Whether this is an SD-JWT+KB (has a Key Binding JWT). */
    public function hasKeyBinding(): bool
    {
        return $this->keyBindingJwt !== null;
    }

    public function withoutKeyBinding(): self
    {
        return new self($this->issuerSignedJwt, $this->disclosures, null);
    }

    /** The decoded JOSE header of the Issuer-signed JWT. */
    public function header(): stdClass
    {
        return JwtParts::parse($this->issuerSignedJwt)->header();
    }

    /**
     * The decoded, UNPROCESSED payload of the Issuer-signed JWT — digests and
     * `_sd` structures included, signature not checked.
     */
    public function payload(): stdClass
    {
        return JwtParts::parse($this->issuerSignedJwt)->payload();
    }

    /** The compact serialization, including the trailing `~` when there is no KB-JWT. */
    public function toCompact(): string
    {
        $result = $this->issuerSignedJwt . '~';

        foreach ($this->disclosures as $disclosure) {
            $result .= $disclosure->encoded . '~';
        }

        return $result . ($this->keyBindingJwt ?? '');
    }
}
