<?php

declare(strict_types=1);

namespace K2gl\SdJwt\Tests;

use K2gl\SdJwt\Exception\InvalidSdJwtException;
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\Tests\Support\SdJwtTestCase;
use K2gl\SdJwt\VerifiedSdJwt;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The JWS JSON serialization of RFC 9901 Section 8, checked against the
 * spec's own Flattened and General examples.
 */
#[CoversClass(SdJwt::class)]
#[CoversClass(VerifiedSdJwt::class)]
#[CoversClass(Presentation::class)]
final class JwsJsonSerializationTest extends SdJwtTestCase
{
    private const RFC_CLOCK = 1748537300;

    public function testParsesTheFlattenedIssuanceExample(): void
    {
        // arrange
        $json = self::fixture('rfc9901/jws-json-flattened-issuance.json');

        // act
        $sdJwt = SdJwt::parse($json);

        // assert: shape
        fact($sdJwt->disclosures)->count(4);
        fact($sdJwt->hasKeyBinding())->false();
        fact($sdJwt->additionalSignatures)->isEmptyArray();
        fact($sdJwt->header()->typ)->is('example+sd-jwt');

        // assert: the Issuer-signed JWT is protected.payload.signature
        $decoded = json_decode($json, true);
        fact($sdJwt->issuerSignedJwt)->is($decoded['protected'] . '.' . $decoded['payload'] . '.' . $decoded['signature']);
    }

    public function testVerifiesTheFlattenedIssuanceExample(): void
    {
        // act
        $verified = $this->verifier()->verify(self::fixture('rfc9901/jws-json-flattened-issuance.json'), self::rfcIssuerKey());
        $claims = $verified->claims();

        // assert: the four Disclosures resolve
        fact($claims['sub'])->is('john_doe_42');
        fact($claims['given_name'])->is('John');
        fact($claims['family_name'])->is('Doe');
        fact($claims['birthdate'])->is('1940-01-01');

        // assert: every Disclosure is reported by its path (order follows the _sd digests)
        $paths = $verified->disclosedPaths();
        sort($paths);
        fact($paths)->is(['/birthdate', '/family_name', '/given_name', '/sub']);
    }

    public function testVerifiesTheFlattenedPresentationWithKeyBinding(): void
    {
        // act: the sd_hash is computed over the compact form rebuilt from the JSON parts (Section 8.1)
        $verified = $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/jws-json-flattened-kb.json'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );

        // assert
        fact($verified->claims()['family_name'])->is('Doe');
        fact($verified->claims()['given_name'])->is('John');
        fact($verified->keyBindingPayload()?->sd_hash)->is('VjtPsgZpQTRxKJvDpSJ-nXlZKE9Z9LgD4FyCwwoNMRw');
    }

    public function testParsesTheGeneralPresentationExample(): void
    {
        // act
        $sdJwt = SdJwt::parse(self::fixture('rfc9901/jws-json-general-kb.json'));

        // assert: Disclosures and the KB-JWT come from the first signature, the second is carried along
        fact($sdJwt->disclosures)->count(2);
        fact($sdJwt->hasKeyBinding())->true();
        fact($sdJwt->unprotectedHeader)->is(['kid' => 'issuer-key-1']);
        fact($sdJwt->additionalSignatures)->count(1);
        fact($sdJwt->additionalSignatures[0]['header'])->is(['kid' => 'issuer-key-2']);
    }

    public function testVerifiesTheGeneralPresentation(): void
    {
        // act: the first signature is the Issuer's; the second is unknown and left alone
        $verified = $this->verifier()->verifyPresentation(
            self::fixture('rfc9901/jws-json-general-kb.json'),
            self::rfcIssuerKey(),
            KeyBinding::required(audience: 'https://verifier.example.org', nonce: '1234567890'),
        );

        // assert
        fact($verified->claims()['family_name'])->is('Doe');
        fact($verified->keyBindingPayload())->notNull();
    }

    #[DataProvider('rfcJsonExamples')]
    public function testReEmitsTheRfcExamplesUnchanged(string $fixture): void
    {
        // arrange
        $json = self::fixture($fixture);

        // act
        $sdJwt = SdJwt::parse($json);

        // assert: same document, member for member
        fact($sdJwt->toJson())->matchesJson($json);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function rfcJsonExamples(): array
    {
        return [
            'flattened issuance'    => ['rfc9901/jws-json-flattened-issuance.json'],
            'flattened SD-JWT+KB'   => ['rfc9901/jws-json-flattened-kb.json'],
            'general SD-JWT+KB'     => ['rfc9901/jws-json-general-kb.json'],
        ];
    }

    public function testRoundTripsCompactThroughJson(): void
    {
        // arrange
        $compact = self::fixture('rfc9901/presentation-sd-jwt-kb.txt');

        // act
        $viaFlattened = SdJwt::parse(SdJwt::parse($compact)->toJson());
        $viaGeneral = SdJwt::parse(SdJwt::parse($compact)->toJson(general: true));

        // assert
        fact($viaFlattened->toCompact())->is($compact);
        fact($viaGeneral->toCompact())->is($compact);
        fact(SdJwt::parse($compact)->toJson(general: true))->hasJsonPath('signatures.0.header.kb_jwt');
    }

    public function testOmitsTheUnprotectedHeaderWhenThereIsNothingToPutInIt(): void
    {
        // arrange
        $sdJwt = SdJwt::parse(self::fixture('rfc9901/issuer-signed-jwt.txt') . '~');

        // act + assert
        fact($sdJwt->toJson())->notHasJsonPath('header');
        fact($sdJwt->toJson(general: true))->notHasJsonPath('signatures.0.header');
    }

    public function testFlatteningSeveralSignaturesIsRefused(): void
    {
        // arrange
        $general = SdJwt::parse(self::fixture('rfc9901/jws-json-general-kb.json'));

        // act + assert
        fact(static fn () => $general->toJson(general: false))
            ->throws(InvalidSdJwtException::class, 'needs the General JSON serialization');

        // assert: the default keeps every signature
        fact($general->toJson())->hasJsonPath('signatures.1.signature');
    }

    public function testPresentationsSerializeToJson(): void
    {
        // arrange
        $issued = (new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts()))->issue([
            'iss' => 'https://issuer.example.com',
            'given_name' => Sd::hide('John'),
            'family_name' => Sd::hide('Doe'),
        ]);

        // act
        $json = Presentation::of($issued)->disclose('/given_name')->toJson();

        // assert: one Disclosure travels, and the JSON form verifies like the compact one
        fact($json)->jsonPath('protected', explode('.', $issued->issuerSignedJwt)[0]);
        fact($this->verifier()->verify($json, self::issuerKey())->claims())->is([
            'iss' => 'https://issuer.example.com',
            'given_name' => 'John',
        ]);
    }

    public function testReportsNestedDisclosedPaths(): void
    {
        // arrange
        $issued = (new SdJwtIssuer(self::issuerSigner(), saltGenerator: self::salts()))->issue([
            'iss' => 'https://issuer.example.com',
            'address' => Sd::hide(['street' => Sd::hide('42 Market Street'), 'country' => 'US']),
        ]);

        // act
        $verified = $this->verifier()->verify($issued, self::issuerKey());

        // assert
        fact($verified->disclosedPaths())->is(['/address', '/address/street']);
    }

    #[DataProvider('malformedDocuments')]
    public function testRejectsMalformedDocuments(string $json, string $message): void
    {
        // act + assert
        fact(static fn () => SdJwt::fromJson($json))->throws(InvalidSdJwtException::class, $message);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function malformedDocuments(): array
    {
        $issuance = json_decode(self::fixture('rfc9901/jws-json-flattened-issuance.json'), true);
        $general = json_decode(self::fixture('rfc9901/jws-json-general-kb.json'), true);

        $disclosuresInSecond = $general;
        $disclosuresInSecond['signatures'][1]['header']['disclosures'] = ['WyJhIiwgImIiLCAiYyJd'];
        $kbInSecond = $general;
        $kbInSecond['signatures'][1]['header']['kb_jwt'] = 'a.b.c';

        $encode = static fn (array $document): string => (string) json_encode($document);

        return [
            'not an object'              => ['[1, 2]', 'expected a JSON object'],
            'payload missing'            => [$encode(array_diff_key($issuance, ['payload' => 1])), '"payload" must be a non-empty string'],
            'protected missing'          => [$encode(array_diff_key($issuance, ['protected' => 1])), 'has no "protected" header'],
            'signature missing'          => [$encode(array_diff_key($issuance, ['signature' => 1])), 'has no "signature"'],
            'header is a list'           => [$encode(['header' => [1]] + $issuance), '"header" of the JWS must be an object'],
            'disclosures not a list'     => [$encode(['header' => ['disclosures' => 'x']] + $issuance), '"disclosures" must be an array of strings'],
            'disclosure not a string'    => [$encode(['header' => ['disclosures' => [1]]] + $issuance), '"disclosures" must be an array of strings'],
            'kb_jwt empty'               => [$encode(['header' => ['kb_jwt' => '']] + $issuance), '"kb_jwt" must be a non-empty string'],
            'signatures empty'           => [$encode(['payload' => $general['payload'], 'signatures' => []]), '"signatures" must be a non-empty array'],
            'signature not an object'    => [$encode(['payload' => $general['payload'], 'signatures' => ['x']]), 'signature 1 is not an object'],
            'disclosures in signature 2' => [$encode($disclosuresInSecond), 'belong to the first signature only (found in signature 2)'],
            'kb_jwt in signature 2'      => [$encode($kbInSecond), 'belong to the first signature only'],
        ];
    }

    private function verifier(): SdJwtVerifier
    {
        return new SdJwtVerifier(clock: self::RFC_CLOCK);
    }
}
