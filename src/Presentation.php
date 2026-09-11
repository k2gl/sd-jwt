<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Exception\SelectionException;
use K2gl\SdJwt\Internal\DisclosureProcessor;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\Internal\Json;
use K2gl\SdJwt\Internal\ProcessedSdJwt;
use K2gl\SdJwt\Jws\JwsSigner;
use stdClass;

/**
 * Holder-side presentation building (RFC 9901 Section 7.2): select which
 * Disclosures to release, optionally add a Key Binding JWT.
 *
 * Selection uses JSON Pointers into the fully disclosed payload (the view
 * returned by {@see claims()}); selecting a nested disclosure automatically
 * includes the parent Disclosures it depends on.
 *
 * ```php
 * $compact = Presentation::of($sdJwt)
 *     ->disclose('/given_name', '/nationalities/0')
 *     ->withKeyBinding($holderSigner, audience: 'https://verifier.example.org', nonce: $nonce);
 * ```
 *
 * Note: this validates structure only. On receipt of an SD-JWT, the Holder
 * should verify the Issuer signature with {@see SdJwtVerifier::verify()}.
 */
final class Presentation
{
    /** @var array<string, true> */
    private array $selected = [];

    private function __construct(
        private readonly SdJwt $sdJwt,
        private readonly ProcessedSdJwt $processed,
    ) {}

    public static function of(SdJwt|string $sdJwt): self
    {
        if (is_string($sdJwt)) {
            $sdJwt = SdJwt::parse($sdJwt);
        }

        if ($sdJwt->hasKeyBinding()) {
            throw new InvalidSdJwtException('Expected an SD-JWT from the Issuer, got an SD-JWT+KB.');
        }

        $payload = $sdJwt->payload();
        $hashAlgorithm = self::hashAlgorithm($payload);

        return new self($sdJwt, DisclosureProcessor::process($payload, $sdJwt->disclosures, $hashAlgorithm));
    }

    /** The fully disclosed payload, for deciding what to release. */
    public function payload(): stdClass
    {
        return $this->processed->payload;
    }

    /**
     * The fully disclosed payload as an associative array.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        /** @var array<string, mixed> */
        return (array) json_decode(Json::encode($this->processed->payload), true);
    }

    /**
     * JSON Pointers of every selectively disclosable claim, relative to
     * {@see payload()}.
     *
     * @return list<string>
     */
    public function disclosablePaths(): array
    {
        return array_keys($this->processed->disclosureByPath);
    }

    /**
     * Select claims to disclose by JSON Pointer (e.g. `/given_name`,
     * `/nationalities/0`). Parent Disclosures required to "connect" a nested
     * claim to the payload are included automatically.
     */
    public function disclose(string ...$paths): self
    {
        $clone = clone $this;

        foreach ($paths as $path) {
            $disclosure = $this->processed->disclosureByPath[$path] ?? null;

            if ($disclosure === null) {
                throw new SelectionException(sprintf(
                    'No selectively disclosable claim at "%s". Available: %s.',
                    $path,
                    implode(', ', $this->disclosablePaths()) ?: '(none)',
                ));
            }

            $digest = $disclosure->digest($this->processed->hashAlgorithm);

            while ($digest !== null) {
                $clone->selected[$digest] = true;
                $digest = $this->processed->parentDigestByDigest[$digest] ?? null;
            }
        }

        return $clone;
    }

    /** Select every Disclosure. */
    public function discloseAll(): self
    {
        $clone = clone $this;

        foreach ($this->processed->disclosureByDigest as $digest => $disclosure) {
            $clone->selected[$digest] = true;
        }

        return $clone;
    }

    /** The presentation as an SD-JWT with only the selected Disclosures. */
    public function toSdJwt(): SdJwt
    {
        $disclosures = [];

        foreach ($this->sdJwt->disclosures as $disclosure) {
            if (isset($this->selected[$disclosure->digest($this->processed->hashAlgorithm)])) {
                $disclosures[] = $disclosure;
            }
        }

        return SdJwt::create($this->sdJwt->issuerSignedJwt, $disclosures);
    }

    /** The compact SD-JWT presentation (no Key Binding). */
    public function toCompact(): string
    {
        return $this->toSdJwt()->toCompact();
    }

    /** The presentation in the JWS JSON serialization (RFC 9901 Section 8), no Key Binding. */
    public function toJson(): string
    {
        return $this->toSdJwt()->toJson();
    }

    /**
     * The compact SD-JWT+KB presentation: the selected Disclosures plus a Key
     * Binding JWT (RFC 9901 Section 4.3) signed with the Holder's key.
     */
    public function withKeyBinding(
        JwsSigner $signer,
        string $audience,
        string $nonce,
        ?int $issuedAt = null,
    ): string {
        $sdJwtCompact = $this->toCompact();

        $keyBindingJwt = $signer->sign(
            payload: [
                'nonce' => $nonce,
                'aud' => $audience,
                'iat' => $issuedAt ?? time(),
                'sd_hash' => HashAlgorithm::digest($this->processed->hashAlgorithm, $sdJwtCompact),
            ],
            header: ['typ' => 'kb+jwt'],
        );

        return $sdJwtCompact . $keyBindingJwt;
    }

    private static function hashAlgorithm(stdClass $payload): string
    {
        $alg = get_object_vars($payload)['_sd_alg'] ?? HashAlgorithm::DEFAULT;

        if (! is_string($alg) || ! HashAlgorithm::isSupported($alg)) {
            throw new InvalidSdJwtException('Unsupported or malformed "_sd_alg" claim.');
        }

        return $alg;
    }
}
