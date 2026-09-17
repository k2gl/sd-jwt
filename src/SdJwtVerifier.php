<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use K2gl\Dsse\PublicKey;
use K2gl\Dsse\Verifier;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Exception\KeyBindingVerificationFailed;
use K2gl\SdJwt\Exception\SignatureVerificationFailed;
use K2gl\SdJwt\Internal\DisclosureProcessor;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\Internal\Json;
use K2gl\SdJwt\Internal\JwtParts;
use K2gl\SdJwt\Internal\ProcessedSdJwt;
use stdClass;
use Throwable;

/**
 * Verifies SD-JWTs and SD-JWT+KB presentations per RFC 9901 Section 7:
 * Issuer signature, Disclosure processing, time-based claims, and — for
 * presentations — the Key Binding JWT against the Verifier's policy.
 *
 * ```php
 * $verifier = new SdJwtVerifier();
 *
 * // Holder side, after receiving an SD-JWT from the Issuer:
 * $verified = $verifier->verify($compact, PublicKey::fromJwk($issuerJwk));
 *
 * // Verifier side, after receiving a presentation from a Holder:
 * $verified = $verifier->verifyPresentation(
 *     $compact,
 *     PublicKey::fromJwk($issuerJwk),
 *     KeyBinding::required(audience: 'https://verifier.example.org', nonce: $nonce),
 * );
 * ```
 */
final class SdJwtVerifier
{
    public const DEFAULT_ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'RS256', 'RS384', 'RS512'];

    public const DEFAULT_HASH_ALGORITHMS = ['sha-256', 'sha-384', 'sha-512'];

    /**
     * @param list<string> $allowedAlgorithms JOSE `alg` values accepted for both JWTs
     * @param list<string> $allowedHashAlgorithms `_sd_alg` values accepted
     * @param ?int $clock Unix time used for `exp`/`nbf`/KB `iat` checks; defaults to time()
     */
    public function __construct(
        private readonly array $allowedAlgorithms = self::DEFAULT_ALGORITHMS,
        private readonly array $allowedHashAlgorithms = self::DEFAULT_HASH_ALGORITHMS,
        private readonly ?int $clock = null,
        private readonly int $clockLeewaySeconds = 0,
    ) {}

    /**
     * Verify an SD-JWT (e.g. as received from the Issuer). A presentation
     * carrying a Key Binding JWT is rejected — use
     * {@see verifyPresentation()} for those.
     */
    public function verify(SdJwt|string $sdJwt, Verifier $issuerKey): VerifiedSdJwt
    {
        $sdJwt = self::parsed($sdJwt);

        if ($sdJwt->hasKeyBinding()) {
            throw new InvalidSdJwtException('Expected an SD-JWT, got an SD-JWT+KB.');
        }

        return self::verified($this->verifySdJwt($sdJwt, $issuerKey), null);
    }

    /**
     * Verify a presentation from a Holder: an SD-JWT+KB when Key Binding is
     * required, otherwise a plain SD-JWT (a KB-JWT, if present anyway, is
     * ignored per the policy).
     */
    public function verifyPresentation(
        SdJwt|string $presentation,
        Verifier $issuerKey,
        KeyBinding $keyBinding,
    ): VerifiedSdJwt {
        $presentation = self::parsed($presentation);

        if (! $keyBinding->required) {
            return self::verified($this->verifySdJwt($presentation->withoutKeyBinding(), $issuerKey), null);
        }

        if (! $presentation->hasKeyBinding()) {
            throw new KeyBindingVerificationFailed('Key Binding is required, but the presentation is a plain SD-JWT.');
        }

        $processed = $this->verifySdJwt($presentation->withoutKeyBinding(), $issuerKey);

        $keyBindingPayload = $this->verifyKeyBinding(
            presentation: $presentation,
            processedPayload: $processed->payload,
            hashAlgorithm: $processed->hashAlgorithm,
            policy: $keyBinding,
        );

        return self::verified($processed, $keyBindingPayload);
    }

    private static function verified(ProcessedSdJwt $processed, ?stdClass $keyBindingPayload): VerifiedSdJwt
    {
        return new VerifiedSdJwt(
            payload: $processed->payload,
            keyBindingPayload: $keyBindingPayload,
            disclosedPaths: $processed->disclosedPaths,
            undisclosedPaths: $processed->undisclosedPaths,
        );
    }

    /** RFC 9901 Section 7.1: signature, `_sd_alg`, Disclosures, time claims. */
    private function verifySdJwt(SdJwt $sdJwt, Verifier $issuerKey): ProcessedSdJwt
    {
        $jwt = JwtParts::parse($sdJwt->issuerSignedJwt);
        $this->checkAlgorithm($jwt->header(), 'Issuer-signed JWT');

        if (! $issuerKey->verify($jwt->signingInput(), $jwt->signature())) {
            throw new SignatureVerificationFailed('The Issuer-signed JWT signature does not verify.');
        }

        $payload = $jwt->payload();
        $hashAlgorithm = $this->hashAlgorithm($payload);
        $processed = DisclosureProcessor::process($payload, $sdJwt->disclosures, $hashAlgorithm);
        $this->checkTimeClaims($processed->payload);

        return $processed;
    }

    /** RFC 9901 Sections 4.3.2 and 7.3, step 5. */
    private function verifyKeyBinding(
        SdJwt $presentation,
        stdClass $processedPayload,
        string $hashAlgorithm,
        KeyBinding $policy,
    ): stdClass {
        $jwt = self::keyBindingJwt($presentation);
        $header = $jwt->header();

        if (($header->typ ?? null) !== 'kb+jwt') {
            throw new KeyBindingVerificationFailed('The Key Binding JWT "typ" header must be "kb+jwt".');
        }

        try {
            $this->checkAlgorithm($header, 'Key Binding JWT');
        } catch (SignatureVerificationFailed $e) {
            throw new KeyBindingVerificationFailed($e->getMessage(), previous: $e);
        }

        $jwk = self::holderJwk($processedPayload);
        $algorithm = is_string($header->alg ?? null) ? $header->alg : '';

        if (! in_array($algorithm, self::algorithmsForJwk($jwk), true)) {
            throw new KeyBindingVerificationFailed(sprintf(
                'The Key Binding JWT algorithm "%s" does not match the Holder key in "cnf".',
                $algorithm,
            ));
        }

        if (! self::holderVerifier($jwk)->verify($jwt->signingInput(), $jwt->signature())) {
            throw new KeyBindingVerificationFailed('The Key Binding JWT signature does not verify.');
        }

        $payload = $jwt->payload();
        $now = $this->now();
        $issuedAt = $payload->iat ?? null;

        if (! is_int($issuedAt) && ! is_float($issuedAt)) {
            throw new KeyBindingVerificationFailed('The Key Binding JWT "iat" claim is missing or not a number.');
        }

        if ($issuedAt < $now - $policy->maxAgeSeconds - $this->clockLeewaySeconds
            || $issuedAt > $now + $this->clockLeewaySeconds) {
            throw new KeyBindingVerificationFailed('The Key Binding JWT "iat" is outside the acceptable window.');
        }

        if (($payload->aud ?? null) !== $policy->audience) {
            throw new KeyBindingVerificationFailed('The Key Binding JWT "aud" claim does not match this Verifier.');
        }

        if (($payload->nonce ?? null) !== $policy->nonce) {
            throw new KeyBindingVerificationFailed('The Key Binding JWT "nonce" claim does not match the challenge.');
        }

        $expectedHash = HashAlgorithm::digest($hashAlgorithm, $presentation->withoutKeyBinding()->toCompact());

        if (! hash_equals($expectedHash, is_string($payload->sd_hash ?? null) ? $payload->sd_hash : '')) {
            throw new KeyBindingVerificationFailed('The Key Binding JWT "sd_hash" does not match the presentation.');
        }

        return $payload;
    }

    private function checkAlgorithm(stdClass $header, string $what): void
    {
        $algorithm = $header->alg ?? null;

        if (! is_string($algorithm) || $algorithm === 'none') {
            throw new SignatureVerificationFailed(sprintf('The %s must carry a signing "alg" header.', $what));
        }

        if (! in_array($algorithm, $this->allowedAlgorithms, true)) {
            throw new SignatureVerificationFailed(sprintf(
                'The %s algorithm "%s" is not allowed.',
                $what,
                $algorithm,
            ));
        }
    }

    private function hashAlgorithm(stdClass $payload): string
    {
        $algorithm = get_object_vars($payload)['_sd_alg'] ?? HashAlgorithm::DEFAULT;

        if (! is_string($algorithm)
            || ! in_array($algorithm, $this->allowedHashAlgorithms, true)
            || ! HashAlgorithm::isSupported($algorithm)) {
            throw new InvalidSdJwtException('Unsupported or malformed "_sd_alg" claim.');
        }

        return $algorithm;
    }

    private function checkTimeClaims(stdClass $payload): void
    {
        $now = $this->now();

        foreach (['exp', 'nbf'] as $claim) {
            $value = $payload->{$claim} ?? null;

            if ($value === null) {
                continue;
            }

            if (! is_int($value) && ! is_float($value)) {
                throw new InvalidSdJwtException(sprintf('The "%s" claim is not a number.', $claim));
            }

            if ($claim === 'exp' && $now >= $value + $this->clockLeewaySeconds) {
                throw new InvalidSdJwtException('The SD-JWT is expired ("exp").');
            }

            if ($claim === 'nbf' && $now < $value - $this->clockLeewaySeconds) {
                throw new InvalidSdJwtException('The SD-JWT is not yet valid ("nbf").');
            }
        }
    }

    private function now(): int
    {
        return $this->clock ?? time();
    }

    private static function keyBindingJwt(SdJwt $presentation): JwtParts
    {
        try {
            return JwtParts::parse((string) $presentation->keyBindingJwt);
        } catch (InvalidSdJwtException $e) {
            throw new KeyBindingVerificationFailed('Malformed Key Binding JWT: ' . $e->getMessage(), previous: $e);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function holderJwk(stdClass $processedPayload): array
    {
        $cnf = get_object_vars($processedPayload)['cnf'] ?? null;
        $jwk = $cnf instanceof stdClass ? (get_object_vars($cnf)['jwk'] ?? null) : null;

        if (! $jwk instanceof stdClass) {
            throw new KeyBindingVerificationFailed(
                'The SD-JWT does not carry a Holder public key in the "cnf" claim ("jwk" member).',
            );
        }

        /** @var array<string, mixed> */
        return (array) json_decode(Json::encode($jwk), true);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function holderVerifier(array $jwk): Verifier
    {
        try {
            return PublicKey::fromJwk($jwk);
        } catch (Throwable $e) {
            throw new KeyBindingVerificationFailed('Unable to use the Holder key from "cnf": ' . $e->getMessage(), previous: $e);
        }
    }

    /**
     * The JOSE algorithms a `cnf` JWK can legitimately sign with; k2gl/dsse
     * verifiers pin the hash per key type (RSA verifies as RS256).
     *
     * @param array<string, mixed> $jwk
     * @return list<string>
     */
    private static function algorithmsForJwk(array $jwk): array
    {
        $kty = $jwk['kty'] ?? null;
        $crv = $jwk['crv'] ?? null;

        return match (true) {
            $kty === 'EC' && $crv === 'P-256' => ['ES256'],
            $kty === 'EC' && $crv === 'P-384' => ['ES384'],
            $kty === 'EC' && $crv === 'P-521' => ['ES512'],
            $kty === 'OKP' && $crv === 'Ed25519' => ['EdDSA'],
            $kty === 'RSA' => ['RS256'],
            default => [],
        };
    }

    private static function parsed(SdJwt|string $sdJwt): SdJwt
    {
        return is_string($sdJwt) ? SdJwt::parse($sdJwt) : $sdJwt;
    }
}
