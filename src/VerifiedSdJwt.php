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
    public function __construct(
        private readonly stdClass $payload,
        private readonly ?stdClass $keyBindingPayload,
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

    /** The payload of the verified Key Binding JWT, when one was checked. */
    public function keyBindingPayload(): ?stdClass
    {
        return $this->keyBindingPayload;
    }
}
