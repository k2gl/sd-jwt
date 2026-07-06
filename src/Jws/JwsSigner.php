<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Jws;

use K2gl\Dsse\EcdsaP256Signer;
use K2gl\Dsse\EcdsaP384Signer;
use K2gl\Dsse\EcdsaP521Signer;
use K2gl\Dsse\Ed25519Signer;
use K2gl\Dsse\RsaSigner;
use K2gl\Dsse\Signer;
use K2gl\SdJwt\Exception\SdJwtException;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\Internal\Json;
use stdClass;

/**
 * Signs compact JWSs with a JOSE `alg` identifier, backed by a k2gl/dsse
 * {@see Signer} (which already emits raw JOSE-style signatures).
 */
final class JwsSigner
{
    private function __construct(
        private readonly Signer $signer,
        private readonly string $algorithm,
    ) {}

    /** ES256: ECDSA over P-256 with SHA-256, key loaded from a PEM string. */
    public static function es256FromPem(string $pem): self
    {
        return new self(EcdsaP256Signer::fromPem($pem), 'ES256');
    }

    /** ES384: ECDSA over P-384 with SHA-384, key loaded from a PEM string. */
    public static function es384FromPem(string $pem): self
    {
        return new self(EcdsaP384Signer::fromPem($pem), 'ES384');
    }

    /** ES512: ECDSA over P-521 with SHA-512, key loaded from a PEM string. */
    public static function es512FromPem(string $pem): self
    {
        return new self(EcdsaP521Signer::fromPem($pem), 'ES512');
    }

    /** EdDSA: Ed25519 with a 64-byte libsodium secret key. */
    public static function ed25519(string $secretKey): self
    {
        if ($secretKey === '') {
            throw new SdJwtException('Empty Ed25519 secret key.');
        }

        return new self(new Ed25519Signer($secretKey), 'EdDSA');
    }

    /** RS256: RSASSA-PKCS1-v1_5 with SHA-256, key loaded from a PEM string. */
    public static function rs256FromPem(string $pem): self
    {
        return new self(RsaSigner::fromPem($pem), 'RS256');
    }

    /**
     * Any other k2gl/dsse Signer paired with the JOSE `alg` value its
     * signatures correspond to (e.g. a KMS-backed signer).
     */
    public static function withAlgorithm(Signer $signer, string $algorithm): self
    {
        return new self($signer, $algorithm);
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Sign a compact JWS. `alg` (and `kid`, when the underlying signer
     * carries a key id) is set automatically; $header may add or override
     * anything else, e.g. `typ`.
     *
     * @param array<string, mixed>|stdClass $payload
     * @param array<string, mixed> $header
     */
    public function sign(array|stdClass $payload, array $header = []): string
    {
        $joseHeader = ['alg' => $this->algorithm];
        $keyId = $this->signer->keyId();

        if ($keyId !== null) {
            $joseHeader['kid'] = $keyId;
        }

        $joseHeader = array_merge($joseHeader, $header);

        $signingInput = Base64Url::encode(Json::encode($joseHeader))
            . '.'
            . Base64Url::encode(Json::encode($payload));

        return $signingInput . '.' . Base64Url::encode($this->signer->sign($signingInput));
    }
}
