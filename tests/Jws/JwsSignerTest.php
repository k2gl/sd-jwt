<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests\Jws;

use K2gl\Dsse\EcdsaP256Signer;
use K2gl\Dsse\Ed25519Verifier;
use K2gl\SdJwt\Exception\SdJwtException;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use stdClass;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(JwsSigner::class)]
final class JwsSignerTest extends SdJwtTestCase
{
    public function testEs256SignaturesVerify(): void
    {
        // act
        $jwt = self::issuerSigner()->sign(payload: ['sub' => 'user_42'], header: ['typ' => 'example+sd-jwt']);
        [$h, $p, $s] = explode('.', $jwt);

        // assert
        fact(json_decode(Base64Url::decode($h), true))->is(['alg' => 'ES256', 'typ' => 'example+sd-jwt']);
        fact(json_decode(Base64Url::decode($p), true))->is(['sub' => 'user_42']);
        fact(self::issuerKey()->verify($h . '.' . $p, Base64Url::decode($s)))->true();
    }

    public function testEd25519SignaturesVerify(): void
    {
        // arrange
        $keypair = sodium_crypto_sign_keypair();
        $signer = JwsSigner::ed25519(sodium_crypto_sign_secretkey($keypair));

        // act
        $jwt = $signer->sign(payload: ['a' => 1]);
        [$h, $p, $s] = explode('.', $jwt);
        $verifier = new Ed25519Verifier(sodium_crypto_sign_publickey($keypair));

        // assert
        fact($signer->algorithm())->is('EdDSA');
        fact($verifier->verify($h . '.' . $p, Base64Url::decode($s)))->true();
    }

    public function testHeaderCanOverrideTheAlgorithm(): void
    {
        // act
        $jwt = self::issuerSigner()->sign(payload: [], header: ['alg' => 'CUSTOM']);
        [$h] = explode('.', $jwt);

        // assert
        fact(json_decode(Base64Url::decode($h), true))->is(['alg' => 'CUSTOM']);
    }

    public function testKeyIdPropagatesToTheHeader(): void
    {
        // arrange
        $signer = JwsSigner::withAlgorithm(
            EcdsaP256Signer::fromPem(self::fixture('keys/issuer-es256.pem'), keyId: 'key-1'),
            'ES256',
        );

        // act
        [$h] = explode('.', $signer->sign(payload: []));

        // assert
        fact(json_decode(Base64Url::decode($h), true))->is(['alg' => 'ES256', 'kid' => 'key-1']);
    }

    public function testStdClassPayloadIsSupported(): void
    {
        // arrange
        $payload = new stdClass;
        $payload->nested = new stdClass;

        // act
        $jwt = self::issuerSigner()->sign(payload: $payload);
        [, $p] = explode('.', $jwt);

        // assert
        fact(Base64Url::decode($p))->is('{"nested":{}}');
    }

    public function testEmptyEd25519KeyIsRejected(): void
    {
        // act + assert
        fact(static fn () => JwsSigner::ed25519(''))->throws(SdJwtException::class);
    }
}
