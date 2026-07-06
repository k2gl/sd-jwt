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

#[CoversClass(JwsSigner::class)]
final class JwsSignerTest extends SdJwtTestCase
{
    public function testEs256SignaturesVerify(): void
    {
        $jwt = self::issuerSigner()->sign(payload: ['sub' => 'user_42'], header: ['typ' => 'example+sd-jwt']);
        [$h, $p, $s] = explode('.', $jwt);

        $header = json_decode(Base64Url::decode($h), true);
        self::assertSame(['alg' => 'ES256', 'typ' => 'example+sd-jwt'], $header);
        self::assertSame(['sub' => 'user_42'], json_decode(Base64Url::decode($p), true));
        self::assertTrue(self::issuerKey()->verify($h . '.' . $p, Base64Url::decode($s)));
    }

    public function testHeaderCanOverrideTheAlgorithm(): void
    {
        $jwt = self::issuerSigner()->sign(payload: [], header: ['alg' => 'CUSTOM']);
        [$h] = explode('.', $jwt);

        self::assertSame(['alg' => 'CUSTOM'], json_decode(Base64Url::decode($h), true));
    }

    public function testKeyIdPropagatesToTheHeader(): void
    {
        $signer = JwsSigner::withAlgorithm(
            EcdsaP256Signer::fromPem(self::fixture('keys/issuer-es256.pem'), keyId: 'key-1'),
            'ES256',
        );
        [$h] = explode('.', $signer->sign(payload: []));

        self::assertSame(['alg' => 'ES256', 'kid' => 'key-1'], json_decode(Base64Url::decode($h), true));
    }

    public function testEd25519SignaturesVerify(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $signer = JwsSigner::ed25519(sodium_crypto_sign_secretkey($keypair));

        self::assertSame('EdDSA', $signer->algorithm());

        $jwt = $signer->sign(payload: ['a' => 1]);
        [$h, $p, $s] = explode('.', $jwt);
        $verifier = new Ed25519Verifier(sodium_crypto_sign_publickey($keypair));

        self::assertTrue($verifier->verify($h . '.' . $p, Base64Url::decode($s)));
    }

    public function testEmptyEd25519KeyIsRejected(): void
    {
        $this->expectException(SdJwtException::class);

        JwsSigner::ed25519('');
    }

    public function testStdClassPayloadIsSupported(): void
    {
        $payload = new stdClass;
        $payload->nested = new stdClass;

        $jwt = self::issuerSigner()->sign(payload: $payload);
        [, $p] = explode('.', $jwt);

        self::assertSame('{"nested":{}}', Base64Url::decode($p));
    }
}
