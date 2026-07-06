<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

/**
 * Verifier policy for Key Binding (RFC 9901 Section 7.3). Whether Key
 * Binding is checked is the Verifier's decision and MUST NOT depend on
 * whether the Holder happened to provide a KB-JWT.
 */
final class KeyBinding
{
    private function __construct(
        public readonly bool $required,
        public readonly ?string $audience,
        public readonly ?string $nonce,
        public readonly int $maxAgeSeconds,
    ) {}

    /**
     * Require an SD-JWT+KB whose KB-JWT names this Verifier ($audience),
     * echoes the challenge it issued ($nonce), and was created no longer
     * than $maxAgeSeconds ago.
     */
    public static function required(string $audience, string $nonce, int $maxAgeSeconds = 600): self
    {
        return new self(required: true, audience: $audience, nonce: $nonce, maxAgeSeconds: $maxAgeSeconds);
    }

    /** Accept a plain SD-JWT presentation; any KB-JWT present is ignored. */
    public static function notRequired(): self
    {
        return new self(required: false, audience: null, nonce: null, maxAgeSeconds: 0);
    }
}
