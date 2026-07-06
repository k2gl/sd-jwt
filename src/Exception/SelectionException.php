<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Exception;

/**
 * A disclosure selection referenced a path that is not selectively
 * disclosable in the SD-JWT at hand.
 */
final class SelectionException extends SdJwtException {}
