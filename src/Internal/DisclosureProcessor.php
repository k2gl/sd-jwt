<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use K2gl\SdJwt\Disclosure;
use K2gl\SdJwt\Exception\InvalidSdJwtException;
use stdClass;

/**
 * The verification-side processing algorithm of RFC 9901 Section 7.1, steps
 * 3-5: resolve embedded digests to Disclosures, build the processed payload,
 * and reject the MUST-level violations (duplicate digests, unreferenced
 * Disclosures, reserved claim names, claim name collisions).
 *
 * @internal
 */
final class DisclosureProcessor
{
    /** @var array<string, Disclosure> */
    private array $disclosureByDigest = [];

    /** @var array<string, int> */
    private array $timesSeen = [];

    /** @var array<string, true> */
    private array $used = [];

    /** @var array<string, Disclosure> */
    private array $disclosureByPath = [];

    /** @var list<string> */
    private array $disclosedPaths = [];

    /** @var list<string> */
    private array $undisclosedPaths = [];

    /** @var array<string, string> */
    private array $parentDigestByDigest = [];

    private function __construct(private readonly string $hashAlgorithm) {}

    /**
     * @param list<Disclosure> $disclosures
     */
    public static function process(stdClass $payload, array $disclosures, string $hashAlgorithm): ProcessedSdJwt
    {
        $processor = new self($hashAlgorithm);

        foreach ($disclosures as $disclosure) {
            $digest = $disclosure->digest($hashAlgorithm);

            if (isset($processor->disclosureByDigest[$digest])) {
                throw new InvalidSdJwtException('The same Disclosure appears more than once in the SD-JWT.');
            }

            $processor->disclosureByDigest[$digest] = $disclosure;
        }

        $processed = $processor->processObject($payload, '', '', null, isRoot: true);

        foreach ($processor->disclosureByDigest as $digest => $disclosure) {
            if (! isset($processor->used[$digest])) {
                throw new InvalidSdJwtException(
                    'A Disclosure is not referenced by any digest in the Issuer-signed JWT.',
                );
            }
        }

        return new ProcessedSdJwt(
            payload: $processed,
            hashAlgorithm: $hashAlgorithm,
            disclosureByPath: $processor->disclosureByPath,
            parentDigestByDigest: $processor->parentDigestByDigest,
            disclosureByDigest: $processor->disclosureByDigest,
            disclosedPaths: $processor->disclosedPaths,
            undisclosedPaths: $processor->undisclosedPaths,
        );
    }

    /**
     * Two pointers travel with every node: `$path` into the processed payload
     * (what a Holder selects Disclosures by) and `$issuedPath` into the payload
     * as issued, where array elements keep their position even when the
     * element before them was not disclosed.
     */
    private function processNode(mixed $node, string $path, string $issuedPath, ?string $viaDigest): mixed
    {
        if ($node instanceof stdClass) {
            return $this->processObject($node, $path, $issuedPath, $viaDigest, isRoot: false);
        }

        if (is_array($node)) {
            // JSON-decoded arrays are always lists; array_values() just proves it.
            return $this->processArray(array_values($node), $path, $issuedPath, $viaDigest);
        }

        return $node;
    }

    private function processObject(stdClass $object, string $path, string $issuedPath, ?string $viaDigest, bool $isRoot): stdClass
    {
        $result = new stdClass;

        foreach (get_object_vars($object) as $name => $value) {
            if ($name === '_sd') {
                continue;
            }

            if ($isRoot && $name === '_sd_alg') {
                continue;
            }

            $segment = '/' . self::escapePointer((string) $name);
            $result->{$name} = $this->processNode($value, $path . $segment, $issuedPath . $segment, $viaDigest);
        }

        $embedded = get_object_vars($object)['_sd'] ?? null;

        if ($embedded === null) {
            return $result;
        }

        if (! is_array($embedded) || ! array_is_list($embedded)) {
            throw new InvalidSdJwtException('The "_sd" key must refer to an array of strings.');
        }

        foreach ($embedded as $digest) {
            if (! is_string($digest)) {
                throw new InvalidSdJwtException('The "_sd" key must refer to an array of strings.');
            }

            $disclosure = $this->takeDisclosure($digest);

            if ($disclosure === null) {
                continue; // Decoy or undisclosed: the digest is ignored.
            }

            if ($disclosure->isArrayElement()) {
                throw new InvalidSdJwtException(
                    'A digest in an "_sd" array resolved to an array-element Disclosure.',
                );
            }

            $name = $disclosure->claimName;

            if ($name === '_sd' || $name === '...') {
                throw new InvalidSdJwtException(
                    sprintf('A Disclosure uses the reserved claim name "%s".', $name),
                );
            }

            if (property_exists($result, (string) $name)) {
                throw new InvalidSdJwtException(
                    sprintf('The disclosed claim "%s" already exists at the same level.', $name),
                );
            }

            $segment = '/' . self::escapePointer((string) $name);
            $this->recordDisclosure($digest, $disclosure, $path . $segment, $issuedPath . $segment, $viaDigest);
            $result->{$name} = $this->processNode($disclosure->value, $path . $segment, $issuedPath . $segment, $digest);
        }

        return $result;
    }

    /**
     * @param list<mixed> $elements
     * @return list<mixed>
     */
    private function processArray(array $elements, string $path, string $issuedPath, ?string $viaDigest): array
    {
        $result = [];

        foreach ($elements as $issued => $element) {
            $digest = self::arrayElementDigest($element);
            $issuedElementPath = $issuedPath . '/' . $issued;

            if ($digest === null) {
                $result[] = $this->processNode($element, $path . '/' . count($result), $issuedElementPath, $viaDigest);

                continue;
            }

            $disclosure = $this->takeDisclosure($digest);

            if ($disclosure === null) {
                // Undisclosed array elements (and decoys, which look the same) are
                // removed from the processed payload; their position is kept on record.
                $this->undisclosedPaths[] = $issuedElementPath;

                continue;
            }

            if (! $disclosure->isArrayElement()) {
                throw new InvalidSdJwtException(
                    'A digest in an array element resolved to an object-property Disclosure.',
                );
            }

            $elementPath = $path . '/' . count($result);
            $this->recordDisclosure($digest, $disclosure, $elementPath, $issuedElementPath, $viaDigest);
            $result[] = $this->processNode($disclosure->value, $elementPath, $issuedElementPath, $digest);
        }

        return $result;
    }

    /**
     * Count the digest occurrence (rejecting duplicates) and resolve it to a
     * Disclosure, or null when none matches.
     */
    private function takeDisclosure(string $digest): ?Disclosure
    {
        $this->timesSeen[$digest] = ($this->timesSeen[$digest] ?? 0) + 1;

        if ($this->timesSeen[$digest] > 1) {
            throw new InvalidSdJwtException('A digest value is encountered more than once in the SD-JWT.');
        }

        return $this->disclosureByDigest[$digest] ?? null;
    }

    private function recordDisclosure(string $digest, Disclosure $disclosure, string $path, string $issuedPath, ?string $viaDigest): void
    {
        $this->used[$digest] = true;
        $this->disclosureByPath[$path] = $disclosure;
        $this->disclosedPaths[] = $issuedPath;

        if ($viaDigest !== null) {
            $this->parentDigestByDigest[$digest] = $viaDigest;
        }
    }

    /** The `{"...": "<digest>"}` form of RFC 9901 Section 4.2.4.2, or null. */
    private static function arrayElementDigest(mixed $element): ?string
    {
        if (! $element instanceof stdClass) {
            return null;
        }

        $properties = get_object_vars($element);

        if (count($properties) !== 1 || ! isset($properties['...']) || ! is_string($properties['...'])) {
            return null;
        }

        return $properties['...'];
    }

    private static function escapePointer(string $segment): string
    {
        return str_replace(['~', '/'], ['~0', '~1'], $segment);
    }
}
