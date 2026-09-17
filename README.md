# k2gl/sd-jwt

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/sd-jwt/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/sd-jwt/actions)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/sd-jwt)](https://packagist.org/packages/k2gl/sd-jwt)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/sd-jwt)](https://packagist.org/packages/k2gl/sd-jwt)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%209-2a5ea7)](https://phpstan.org/)
[![License](https://img.shields.io/packagist/l/k2gl/sd-jwt)](https://packagist.org/packages/k2gl/sd-jwt)

Selective Disclosure for JWTs ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901)) in pure
PHP: issue SD-JWTs with selectively disclosable claims, build Holder presentations with
optional Key Binding, and verify both. This is the credential format at the core of
OpenID4VC/HAIP and the EU Digital Identity Wallet.

The test suite is driven by the worked examples embedded in RFC 9901 itself (Sections 4.2
and 5, Appendix A.5 key), verified byte for byte.

Fail-closed by design: every MUST-level rule of the RFC's verification algorithm — duplicate
digests, unreferenced Disclosures, reserved claim names, claim collisions, `alg: none`,
Key Binding mismatches — throws; nothing is silently accepted.

## Install

```bash
composer require k2gl/sd-jwt
```

Requires PHP 8.1+. Crypto is provided by [k2gl/dsse](https://github.com/k2gl/dsse) signers
and verifiers over `ext-openssl` (ES256/ES384/ES512, RS256) and `ext-sodium` (EdDSA).

## Usage

### Issue an SD-JWT

Wrap everything selectively disclosable in `Sd::hide()` — object properties, array
elements, or whole subtrees (nesting produces recursive Disclosures per Section 4.2.6).
`Sd::decoy()` inserts decoy digests.

```php
use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwtIssuer;

$issuer = new SdJwtIssuer(JwsSigner::es256FromPem($issuerPrivatePem));

$sdJwt = $issuer->issue(
    claims: [
        'iss' => 'https://issuer.example.com',
        'iat' => time(),
        'sub' => 'user_42',
        'cnf' => ['jwk' => $holderPublicJwk],       // enables Key Binding
        'given_name' => Sd::hide('John'),
        'address' => Sd::hide([
            'street_address' => Sd::hide('123 Main St'), // recursive
            'country' => 'US',
        ]),
        'nationalities' => [Sd::hide('US'), Sd::hide('DE'), Sd::decoy()],
    ],
    header: ['typ' => 'example+sd-jwt'],
);

$compact = $sdJwt->toCompact(); // <JWT>~<Disclosure>~...~
```

### Present selected claims (Holder)

Selection uses JSON Pointers into the fully disclosed payload; parent Disclosures that a
nested claim depends on are included automatically.

```php
use K2gl\SdJwt\Presentation;

$presentation = Presentation::of($compact);
$presentation->disclosablePaths();  // ['/given_name', '/address', '/address/street_address', ...]

// Without Key Binding:
$toVerifier = $presentation->disclose('/given_name', '/nationalities/0')->toCompact();

// With Key Binding (RFC 9901 Section 4.3):
$toVerifier = $presentation
    ->disclose('/given_name')
    ->withKeyBinding(
        JwsSigner::es256FromPem($holderPrivatePem),
        audience: 'https://verifier.example.org',
        nonce: $nonceFromVerifier,
    );
```

### Verify a presentation (Verifier)

```php
use K2gl\Dsse\PublicKey;
use K2gl\SdJwt\Exception\SdJwtException;
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\SdJwtVerifier;

$verifier = new SdJwtVerifier;

try {
    $verified = $verifier->verifyPresentation(
        $toVerifier,
        PublicKey::fromJwk($issuerPublicJwk),   // or PublicKey::fromPem(...)
        KeyBinding::required(
            audience: 'https://verifier.example.org',
            nonce: $nonceFromVerifier,
        ),
    );

    $claims = $verified->claims();  // the Processed SD-JWT Payload, digests resolved
} catch (SdJwtException $e) {
    // not verified — bad signature, tampered Disclosure, replayed or missing Key Binding, ...
}
```

Use `KeyBinding::notRequired()` for presentations without Holder binding, and
`$verifier->verify($sdJwt, $issuerKey)` on the Holder side after receiving an SD-JWT from
an Issuer.

The verified result also says which claims came through Disclosures and which array
elements were withheld, as JSON Pointers with array positions **as issued** — the
coordinates SD-JWT VC Type Metadata uses to say what may or must be selectively
disclosed:

```php
$verified->claims()['nationalities'];  // ['US', 'FR'] — the middle one was not disclosed
$verified->disclosedPaths();           // ['/nationalities/0', '/nationalities/2', '/address/street']
$verified->undisclosedPaths();         // ['/nationalities/1'] — a decoy digest looks the same
```

### JWS JSON serialization

RFC 9901 Section 8 defines an alternative to the `~`-separated compact form: a JWS JSON
object (RFC 7515 Section 7.2) whose unprotected header carries the Disclosures and, for a
presentation, the Key Binding JWT. Everything above accepts it wherever a compact string is
accepted — `SdJwt::parse()` tells the two apart by the leading `{` — and every SD-JWT can be
emitted in it:

```php
$json = SdJwt::parse($compact)->toJson();               // Flattened (Section 8.2)
$json = SdJwt::parse($compact)->toJson(general: true);  // General (Section 8.3)
$json = $presentation->disclose('/given_name')->toJson();

$verified = $verifier->verifyPresentation($json, $issuerKey, KeyBinding::required(...));
```

A General serialization may carry several signatures; the Disclosures and `kb_jwt` belong to
the first one, and that is the signature verified. The others are kept so that `toJson()`
re-emits the document unchanged — `toCompact()`, which has no room for them, drops them.
The `sd_hash` of a Key Binding JWT is always computed over the compact form rebuilt from the
JSON parts, as Section 8.1 requires.

## Scope

- Compact serialization (`<JWT>~<Disclosure>~...~[<KB-JWT>]`) and the JWS JSON
  serialization (Section 8, Flattened and General) — issue, present, verify.
- Object-property, array-element, and recursive Disclosures; decoy digests.
- Key Binding JWTs: creation and full Section 7.3 validation (`typ`, algorithm-to-`cnf`
  match, `iat` window, `aud`, `nonce`, `sd_hash`).
- `_sd_alg`: sha-256 (default), sha-384, sha-512.
- JOSE algorithms: ES256, ES384, ES512, EdDSA, RS256 (signing); verification takes any
  k2gl/dsse `Verifier`.

## Design

- The encoded Disclosure is authoritative: digests are computed over the base64url string
  exactly as received, never over re-serialized JSON, so foreign encodings survive
  verification untouched.
- Processing keeps the JSON object/array distinction (`stdClass` vs list) end to end;
  `->payload()` returns the lossless view, `->claims()` the convenient array one.
- The verifier is policy-explicit: allowed JOSE algorithms, allowed hash algorithms, clock,
  and leeway are constructor parameters with safe defaults; Key Binding is decided by the
  Verifier's policy, never by what the Holder sent.

## License

MIT © [Nick Harin](https://github.com/k2gl)
