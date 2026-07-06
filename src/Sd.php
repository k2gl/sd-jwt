<?php

declare(strict_types=1);

namespace K2gl\SdJwt;

/**
 * Marker used in the claims passed to {@see SdJwtIssuer::issue()}.
 *
 * Wrap a claim value in `Sd::hide(...)` to make it selectively disclosable;
 * the marker works for object properties and array elements alike and can be
 * nested for recursive disclosures. `Sd::decoy()` inserts a decoy digest at
 * the position where it appears (RFC 9901 Section 4.2.5).
 *
 * ```php
 * $claims = [
 *     'sub' => 'user_42',                       // always visible
 *     'given_name' => Sd::hide('John'),         // object property
 *     'nationalities' => [Sd::hide('US'), 'DE'] // array element
 * ];
 * ```
 */
final class Sd
{
    private function __construct(
        public readonly mixed $value,
        public readonly bool $decoy,
    ) {}

    /** Make this value selectively disclosable. */
    public static function hide(mixed $value): self
    {
        return new self($value, false);
    }

    /** Insert a decoy digest at this position. */
    public static function decoy(): self
    {
        return new self(null, true);
    }
}
