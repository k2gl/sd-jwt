<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use Closure;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\Internal\Base64Url;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\Jws\JwsSigner;
use stdClass;

/**
 * Issues SD-JWTs (RFC 9901 Section 4): claims wrapped in {@see Sd::hide()}
 * become Disclosures, everything else stays in the payload as plaintext.
 *
 * ```php
 * $issuer = new SdJwtIssuer(JwsSigner::es256FromPem($pem));
 *
 * $sdJwt = $issuer->issue(
 *     claims: [
 *         'iss' => 'https://issuer.example.com',
 *         'iat' => time(),
 *         'sub' => 'user_42',
 *         'given_name' => Sd::hide('John'),
 *         'nationalities' => [Sd::hide('US'), Sd::hide('DE')],
 *     ],
 *     header: ['typ' => 'example+sd-jwt'],
 * );
 * ```
 */
final class SdJwtIssuer
{
    private readonly Closure $saltGenerator;

    /**
     * @param ?Closure(): string $saltGenerator Returns one salt per call; defaults
     *                                          to base64url of 16 random bytes.
     */
    public function __construct(
        private readonly JwsSigner $signer,
        private readonly string $hashAlgorithm = HashAlgorithm::DEFAULT,
        ?Closure $saltGenerator = null,
    ) {
        if (! HashAlgorithm::isSupported($hashAlgorithm)) {
            throw new InvalidSdJwtException(sprintf('Unsupported hash algorithm "%s".', $hashAlgorithm));
        }

        $this->saltGenerator = $saltGenerator ?? static fn (): string => Base64Url::encode(random_bytes(16));
    }

    /**
     * @param array<string, mixed>|stdClass $claims The full claims set, with
     *                                              {@see Sd} markers on everything selectively disclosable.
     * @param array<string, mixed> $header Extra JOSE header parameters (e.g. `typ`).
     */
    public function issue(array|stdClass $claims, array $header = []): SdJwt
    {
        /** @var list<Disclosure> $disclosures */
        $disclosures = [];
        $payload = $this->hideObjectProperties($claims, $disclosures);

        if ($disclosures !== []) {
            $payload->_sd_alg = $this->hashAlgorithm;
        }

        return SdJwt::create($this->signer->sign($payload, $header), $disclosures);
    }

    /**
     * @param array<mixed>|stdClass $object
     * @param list<Disclosure> $disclosures
     */
    private function hideObjectProperties(array|stdClass $object, array &$disclosures): stdClass
    {
        $result = new stdClass;
        /** @var list<string> $digests */
        $digests = [];

        foreach (self::properties($object) as $name => $value) {
            if ($name === '_sd' || $name === '...' || $name === '_sd_alg') {
                throw new InvalidSdJwtException(sprintf('"%s" cannot be used as a claim name.', $name));
            }

            if ($value instanceof Sd) {
                $digests[] = $value->decoy
                    ? $this->decoyDigest()
                    : $this->discloseProperty($name, $value->value, $disclosures);

                continue;
            }

            $result->{$name} = $this->hideValue($value, $disclosures);
        }

        if ($digests !== []) {
            sort($digests, SORT_STRING); // Hide the original claim order (Section 4.2.4.1).
            $result->_sd = $digests;
        }

        return $result;
    }

    /**
     * @param list<mixed> $elements
     * @param list<Disclosure> $disclosures
     * @return list<mixed>
     */
    private function hideArrayElements(array $elements, array &$disclosures): array
    {
        $result = [];

        foreach ($elements as $element) {
            if ($element instanceof Sd) {
                $digest = $element->decoy
                    ? $this->decoyDigest()
                    : $this->discloseArrayElement($element->value, $disclosures);

                $result[] = (object) ['...' => $digest];

                continue;
            }

            $result[] = $this->hideValue($element, $disclosures);
        }

        return $result;
    }

    /**
     * @param list<Disclosure> $disclosures
     */
    private function hideValue(mixed $value, array &$disclosures): mixed
    {
        if ($value instanceof Sd) {
            throw new InvalidSdJwtException('Unexpected Sd marker; markers apply to object properties and array elements.');
        }

        if ($value instanceof stdClass) {
            return $this->hideObjectProperties($value, $disclosures);
        }

        if (is_array($value) && array_is_list($value)) {
            return $this->hideArrayElements($value, $disclosures);
        }

        if (is_array($value)) {
            return $this->hideObjectProperties($value, $disclosures);
        }

        return $value;
    }

    /**
     * @param list<Disclosure> $disclosures
     */
    private function discloseProperty(string $name, mixed $value, array &$disclosures): string
    {
        $disclosure = Disclosure::forProperty(
            salt: ($this->saltGenerator)(),
            claimName: $name,
            value: $this->hideValue($value, $disclosures),
        );
        $disclosures[] = $disclosure;

        return $disclosure->digest($this->hashAlgorithm);
    }

    /**
     * @param list<Disclosure> $disclosures
     */
    private function discloseArrayElement(mixed $value, array &$disclosures): string
    {
        $disclosure = Disclosure::forArrayElement(
            salt: ($this->saltGenerator)(),
            value: $this->hideValue($value, $disclosures),
        );
        $disclosures[] = $disclosure;

        return $disclosure->digest($this->hashAlgorithm);
    }

    private function decoyDigest(): string
    {
        return HashAlgorithm::digest($this->hashAlgorithm, ($this->saltGenerator)());
    }

    /**
     * @param array<mixed>|stdClass $object
     * @return array<string, mixed>
     */
    private static function properties(array|stdClass $object): array
    {
        if ($object instanceof stdClass) {
            return get_object_vars($object);
        }

        if ($object !== [] && array_is_list($object)) {
            throw new InvalidSdJwtException('Expected an object (associative array or stdClass), got a list.');
        }

        $properties = [];

        foreach ($object as $name => $value) {
            $properties[(string) $name] = $value;
        }

        return $properties;
    }
}
