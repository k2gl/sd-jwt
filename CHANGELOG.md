# Changelog

## 1.2.0

- `VerifiedSdJwt::undisclosedPaths()` — the JSON Pointers of the array elements whose
  Disclosure was not provided (a decoy digest is indistinguishable and listed the same
  way). Together with `disclosedPaths()` this is what SD-JWT VC Type Metadata needs to check
  its `sd` rules: the draft evaluates array positions against the array as issued.
- Accordingly, array indices in `disclosedPaths()` now count the elements as issued,
  undisclosed ones included; before, they were positions in the processed payload. Object
  keys are unaffected, and so is `Presentation`, which still selects by processed-payload
  pointers.

## 1.1.0

- JWS JSON serialization (RFC 9901 Section 8): `SdJwt::parse()` accepts the Flattened and
  General forms next to the compact one, `SdJwt::toJson()` / `Presentation::toJson()` emit
  them. The RFC's Section 8 examples verify end to end, Key Binding included.
- `VerifiedSdJwt::disclosedPaths()` — the JSON Pointers of the claims that arrived through
  Disclosures, so a profile can enforce which claims may be selectively disclosed.

## 1.0.0

- Initial release: Selective Disclosure for JWTs per RFC 9901.
- `SdJwtIssuer` — issue SD-JWTs with `Sd::hide()` markers for object properties, array
  elements, and recursive Disclosures; `Sd::decoy()` for decoy digests; sha-256/384/512
  `_sd_alg`.
- `Presentation` — Holder-side selection by JSON Pointer with automatic inclusion of parent
  Disclosures, optional Key Binding JWT.
- `SdJwtVerifier` — the full Section 7 verification algorithm with explicit policy (allowed
  algorithms, hash algorithms, clock, leeway) and Key Binding validation per Section 7.3.
- Signing via `JwsSigner` (ES256/ES384/ES512, EdDSA, RS256) backed by k2gl/dsse;
  verification accepts any k2gl/dsse `Verifier`.
- Test vectors: the worked examples of RFC 9901 Sections 4.2 and 5 (issuance, presentation
  with Key Binding, Appendix A.5 key), plus a rejection matrix for the MUST-level rules.
