<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Exception;

/**
 * The Key Binding JWT is missing, malformed, or failed one of the checks of
 * RFC 9901 Section 7.3 (signature, typ, iat window, aud, nonce, sd_hash).
 */
final class KeyBindingVerificationFailed extends SdJwtException {}
