<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

use K2gl\SdJwt\Internal\Json;
use stdClass;

/**
 * The outcome of a successful verification: the Processed SD-JWT Payload
 * (RFC 9901 Section 7.1) with all disclosed claims merged in and every
 * `_sd`/`...`/`_sd_alg` artifact removed.
 */
final class VerifiedSdJwt
{
    /**
     * @param list<string> $disclosedPaths
     * @param list<string> $undisclosedPaths
     */
    public function __construct(
        private readonly stdClass $payload,
        private readonly ?stdClass $keyBindingPayload,
        private readonly array $disclosedPaths = [],
        private readonly array $undisclosedPaths = [],
    ) {}

    /** The Processed SD-JWT Payload; JSON objects are stdClass instances. */
    public function payload(): stdClass
    {
        return $this->payload;
    }

    /**
     * The Processed SD-JWT Payload as an associative array. Convenient, but
     * note that an empty JSON object degrades to an empty PHP array here.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        /** @var array<string, mixed> */
        return (array) json_decode(Json::encode($this->payload), true);
    }

    /**
     * JSON Pointers of every claim that arrived through a Disclosure, e.g.
     * `/address/street_address` — lets a profile decide which claims may or may
     * not be selectively disclosed.
     *
     * Array indices count the elements as issued, undisclosed ones included (see
     * {@see undisclosedPaths()}), which is how SD-JWT VC Type Metadata addresses
     * claims. In the processed payload an element sits at its issued index minus
     * the undisclosed elements before it.
     *
     * @return list<string>
     */
    public function disclosedPaths(): array
    {
        return $this->disclosedPaths;
    }

    /**
     * JSON Pointers, in the array positions as issued, of the array elements
     * whose Disclosure was not provided, e.g. `/nationalities/1` — absent from
     * the processed payload, but their place is known. A decoy digest cannot be
     * told from a withheld element and is listed the same way.
     *
     * @return list<string>
     */
    public function undisclosedPaths(): array
    {
        return $this->undisclosedPaths;
    }

    /** The payload of the verified Key Binding JWT, when one was checked. */
    public function keyBindingPayload(): ?stdClass
    {
        return $this->keyBindingPayload;
    }
}
