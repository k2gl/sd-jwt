<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Exception;

/**
 * The Issuer-signed JWT signature did not verify, or its algorithm is not
 * allowed by the verifier's policy.
 */
final class SignatureVerificationFailed extends SdJwtException {}
