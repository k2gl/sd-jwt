<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Exception;

/**
 * The SD-JWT (or one of its Disclosures) is malformed or violates a
 * MUST-level rule of RFC 9901, e.g. a duplicate digest, an unreferenced
 * Disclosure, or a reserved claim name inside a Disclosure.
 */
final class InvalidSdJwtException extends SdJwtException {}
