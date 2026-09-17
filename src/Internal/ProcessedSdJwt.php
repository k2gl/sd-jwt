<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Internal;

use K2gl\SdJwt\Disclosure;
use stdClass;

/**
 * Result of running the RFC 9901 Section 7.1 processing algorithm: the
 * processed payload plus the bookkeeping needed to select disclosures for a
 * presentation.
 *
 * @internal
 */
final class ProcessedSdJwt
{
    /**
     * @param array<string, Disclosure> $disclosureByPath JSON Pointer (into the processed payload) => Disclosure
     * @param array<string, string> $parentDigestByDigest child digest => digest of the Disclosure whose value contains it
     * @param array<string, Disclosure> $disclosureByDigest
     * @param list<string> $disclosedPaths JSON Pointers, as issued, of the claims that arrived through a Disclosure
     * @param list<string> $undisclosedPaths JSON Pointers, as issued, of array elements whose Disclosure was not provided
     */
    public function __construct(
        public readonly stdClass $payload,
        public readonly string $hashAlgorithm,
        public readonly array $disclosureByPath,
        public readonly array $parentDigestByDigest,
        public readonly array $disclosureByDigest,
        public readonly array $disclosedPaths = [],
        public readonly array $undisclosedPaths = [],
    ) {}
}
