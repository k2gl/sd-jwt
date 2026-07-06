<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests\Support;

use Closure;
use K2gl\Dsse\PublicKey;
use K2gl\Dsse\Verifier;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\Jws\JwsSigner;
use PHPUnit\Framework\TestCase;

abstract class SdJwtTestCase extends TestCase
{
    protected static function fixture(string $relativePath): string
    {
        $contents = file_get_contents(__DIR__ . '/../fixtures/' . $relativePath);
        self::assertNotFalse($contents);

        return trim($contents);
    }

    /** The public key from RFC 9901 Appendix A.5, verifying the RFC examples. */
    protected static function rfcIssuerKey(): Verifier
    {
        /** @var array<string, mixed> $jwk */
        $jwk = json_decode(self::fixture('rfc9901/issuer-public-key.jwk.json'), true);

        return PublicKey::fromJwk($jwk);
    }

    protected static function issuerSigner(): JwsSigner
    {
        return JwsSigner::es256FromPem(self::fixture('keys/issuer-es256.pem'));
    }

    protected static function issuerKey(): Verifier
    {
        return PublicKey::fromPem(self::fixture('keys/issuer-es256.pub.pem'));
    }

    protected static function holderSigner(): JwsSigner
    {
        return JwsSigner::es256FromPem(self::fixture('keys/holder-es256.pem'));
    }

    /**
     * @return array<string, string>
     */
    protected static function holderJwk(): array
    {
        /** @var array<string, string> */
        return json_decode(self::fixture('keys/holder-es256.jwk.json'), true);
    }

    /** A salt generator cycling deterministic values. */
    protected static function salts(): Closure
    {
        $counter = 0;

        return static function () use (&$counter): string {
            return Base64Url::encode(str_pad('salt-' . $counter++, 16, '_'));
        };
    }

    /** Build a compact SD-JWT string from raw parts. */
    protected static function compact(string $jwt, array $disclosures = [], ?string $keyBindingJwt = null): string
    {
        $result = $jwt . '~';

        foreach ($disclosures as $disclosure) {
            $result .= $disclosure . '~';
        }

        return $result . ($keyBindingJwt ?? '');
    }
}
