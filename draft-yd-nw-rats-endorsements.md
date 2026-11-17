---
title: "A CoRIM Profile for Arm's Normal World Attestation Endorsements"
abbrev: "Arm NW Endorsements"
docname: draft-yd-nw-rats-endorsements-latest
category: info

date: {DATE}
category: info
ipr: trust200902
# area: Security
# workgroup: RATS

stand_alone: yes
pi:

  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  text-list-symbols: -o*+
  docmapping: yes

author:

-
  name: Yogesh Deshpande
  org: Arm Ltd
  email: yogesh.deshpande@arm.com

contributor:
 -  name: Simon Frost
    organization: Arm Limited
    email: Simon.Frost@arm.com
 -  name: Sergei Trofimov
    organization: Arm Limited
    email: Sergei.Trofimov@arm.com

normative:
  I-D.ietf-rats-corim: rats-corim
  RFC5280: pkix-x509
  RFC7468: pem
  TBB:
    author:
      org: Arm
    title: Trusted Board Boot
    target: https://trustedfirmware-a.readthedocs.io/en/stable/design/trusted-board-boot.html
    date: 2024-12-30

informative:
  RFC9334: rats-arch

entity:
  SELF: "RFCthis"

--- abstract

Arm Normal World Attestation Endorsements comprise reference values and cryptographic key material that a Verifier needs to appraise Attestation Evidence produced from Normal World client running on an Arm Platform.

This memo defines Normal World Endorsements as a profile of the CoRIM data model.


--- middle

# Introduction

Arm's Normal World Remote Attestation provides a mechanism for a Normal World client to obtain a Remote Attestation token from the underlying Arm platform.

Arm's Normal World Endorsements comprise of reference values and cryptographic key material that an Attestation Verifier requires.
These Endorsements are used to appraise Attestation Evidence produced by a Normal World client running on an Arm platform.

This memo defines Normal World Endorsements as a profile of the CoRIM data model {{-rats-corim}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The reader is assumed to be familiar with the terms and concepts introduced in {{Section 4 of -rats-arch}}.

# Arm NW Endorsements

Arm's Normal World Endorsements comprise of Arm Platform Endorsements.

Appraising Arm Normal World Evidence requires Endorsements for the Arm Platform.
This document outlines the Platform in {{sec-platform-endorsements}}.

It also provides the Evidence transformation logic for conducting appraisals using the CoRIM processor (see {{Section 8 of -rats-corim}}) for platform claim sets.

## Arm Platform Endorsements {#sec-platform-endorsements}

There are two types of Arm Platform Endorsements:

* Reference Values ({{sec-ref-values}}), i.e., measurements of the Arm Platform firmware.
* Attestation Verification Keys ({{sec-keys}}), i.e., cryptographic keys that can be used to verify Evidence produced by the Arm Platform, along with the identifiers that link the keys to their platform instances.

### Arm Platform Endorsement Profile

Arm Platform Endorsements are carried in one or more CoMIDs within a CoRIM.

The profile attribute in the CoRIM MUST be present and MUST be the URI `tag:arm.com,2026:endorsements/arm_nw_platform#1.0.0`, as shown in {{ex-arm-platform-profile}}.

~~~
{::include examples/platform-profile.diag}
~~~
{: #ex-arm-platform-profile title="CoRIM profile for Arm Normal World Platform Endorsements version 1.0.0" }

### Arm Platform Endorsements linkage to Arm Platform {#sec-arm-rot-id}

Each Arm Platform Endorsement, be it a Reference Value or an Attestation Verification Key, is associated with a unique identifier known as Arm Platform Implementation ID.
The Implementation ID uniquely identifies a given implementation of a Arm Platform and it is used by the Endorser or Reference Value Provider as an anchor to which Reference Values and Attestation Verification Keys for a Arm Normal World Platform are linked.

To encode an Implementation ID, the `tagged-bytes` variant of the `$class-id-type-choice` is used, as described in {{cddl-impl-id}}.
The length of the byte string MUST be exactly 32.

~~~ cddl
impl-id-tagged-bytes = #6.560(arm-platform-implementation-id-type)

arm-platform-implementation-id-type = bytes .size 32
~~~
{: #cddl-impl-id title="Arm Platform Implementation ID encoding"}

Besides, a  Arm Platform Endorsement can be associated with a specific *instance* of a certain Arm Platform implementation - as is the case of Attestation Verification Keys.
The Instance ID provides a unique identifier for a given Arm Platform instance.

To encode an Instance ID, the `tagged-ueid-type` variant of the `$instance-id-type-choice` is used, as described in {{cddl-inst-id}}.
The first byte MUST be 0x01 (RAND) followed by the 32-byte unique instance identifier.

~~~ cddl
inst-id-tagged-ueid = #6.550(eat-ueid-rand-type)

eat-ueid-rand-type = bytes .join eat-ueid-rand-fmt

eat-ueid-rand-fmt = [
  ; the type byte is 0x01
  ueid-rand-typ
  bytes .size 32
]

ueid-rand-typ = h'01'
~~~
{: #cddl-inst-id title="Arm Platform Instance ID encoding"}

Arm Attestation Verification Keys are associated with an Arm Platform instance by means of the Instance ID and the corresponding Implementation ID.
These identifiers are typically found in the subject of a CoMID triple, encoded in an `environment-map` as shown in {{ex-arm-platform-id}}.

~~~ cbor-diag
{::include examples/platform-identification.diag}
~~~
{: #ex-arm-platform-id title="Example Arm Platform Identification" }

Together, they are interpreted as a unique identifier of the Arm Platform.


### Reference Values {#sec-ref-values}

Reference Values carry measurements and other metadata associated with the updatable firmware of the Arm Platform.

When appraising Evidence, the Verifier compares Reference Values against:

* The values found in the Software Components of the Arm Normal World Platform token.
* The value set in the platform configuration of the Arm Normal World Platform token.

Each measurement is encoded in a `measurement-map` of a CoMID `reference-triple-record`.
Since a `measurement-map` can encode one or more measurements, a single `reference-triple-record` can carry as many measurements as needed, provided they belong to the same Arm Platform identified in the subject of the triple.
A single `reference-triple-record` MUST completely describe the Arm Platform measurements.

#### Arm Platform Software Components

Each Arm Platform software component is encoded in a `measurement-values-map` as defined in {{cddl-swcomp-mvm}}.

~~~ cddl
arm-swcomp-measurement-values-map = {
  ? &(version: 0) => arm-swcomp-version-map
  &(digests: 2) => arm-swcomp-digests-type
  ? &(name: 11) => arm-swcomp-name
  &(cryptokeys: 13) => [ arm-swcomp-signer-id ]
}

arm-swcomp-version-map = {
  &(version: 0) => text
}

arm-swcomp-digests-type = [ + arm-digest ]

arm-digest = [
  alg: text
  val: arm-hash-type
]

arm-hash-type = bytes .size 32 / bytes .size 48 / bytes .size 64

arm-swcomp-name = text

arm-swcomp-signer-id = #6.560(arm-hash-type)
~~~
{: #cddl-swcomp-mvm title="CCA Platform Software Component encoding"}

{:vspace}
version (key 0):
: A `version-map` with its `version` field containing the version (key 4) of the `arm-platform-sw-component`.
The `version-scheme` field of the `version-map` MUST NOT be present.
This field is optional.

digests (key 2):
: Each array element encodes the "measurement value" (key 2) and "hash algorithm identifier" (key 6) of the `arm-platform-sw-component` in the `val` and `alg` entries, respectively.
The `alg` entry MUST use the text encoding.
The digests array MUST contain at least one entry and MAY contain more than one entry if multiple digests (obtained with different hash algorithms) of the same measured component exist.
If multiple entries exist, they MUST have different `alg` values.
This field is mandatory.

name (key 11):
: A text value containing the "component type" (key 1) of the `arm-platform-sw-component`.
This field is optional.

cryptokeys (key 13):
: An array with *only one* entry using the `tagged-bytes` variant of the `$crypto-key-type-choice`.
The entry contains the "signer id" (key 5) of the `arm-platform-sw-component`.
This field is mandatory.

Each `measurement-values-map` for a CCA Platform software component is wrapped in a `measurement-map` with an `mkey` using the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "cca.software-component".
The `authorized-by` field of the `measurement-map` MUST NOT be present.
Find the related CDDL definitions in {{cddl-swcomp-mm}}.

~~~ cddl
arm-swcomp-measurement-map = {
  &(mkey: 0) => "cca.software-component"
  &(mval: 1) => arm-swcomp-measurement-values-map
}
~~~
{: #cddl-swcomp-mm title="CCA Platform Software Component measurement-map"}

#### CCA Platform Configuration

The CCA Platform configuration describes the set of chosen implementation options of the CCA Platform.
For example, this may include a description of the level of physical memory protection provided.

CCA Platform configuration is vendor-specific variable-length data.
Only some of the data may be security-relevant.
For these reasons, it is represented in a `raw-value` of the `measurement-values-map`, using the `tagged-masked-raw-value` variant of the `$raw-values-type-choice`.
Refer to {{Section 5.1.4.1.4.6 of -rats-corim}} for the details about the comparison algorithm.

~~~ cddl
arm-config-measurement-values-map = {
  &(raw-value: 4) => arm-tagged-masked-raw-value
}

arm-config-tagged-masked-raw-value = #6.563([
  value: bytes
  mask: bytes
])
~~~
{: #cddl-config-mvm title="CCA Platform Configuration measurement-values-map"}

The `measurement-values-map` for a CCA Platform configuration is wrapped in a `measurement-map` with an `mkey` using the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "cca.platform-config".
There MUST be only one `measurement-map` with `mkey` "cca.platform-config" in the triple.

The `authorized-by` field of the `measurement-map` MUST NOT be present.
Find the related CDDL definitions in {{cddl-config-mm}}.

~~~ cddl
arm-config-measurement-map = {
  &(mkey: 0) => "cca.platform-config"
  &(mval: 1) => arm-config-measurement-values-map
}
~~~
{: #cddl-config-mm title="CCA Platform Configuration measurement-map"}

#### Arm Platform Trusted Board Boot ROTPK {#sec-rotpk}

When an implementation of the Arm Platform follows the Trusted Board Boot {{TBB}} specification, the platform will include several provisioned public key identifiers to establish a chain of trust.
Each public key identifier is expressed as a hash of the corresponding public key.

For Arm platform Implementation, the public key identifiers are provisioned as a number of array entries, with each array entry containing a list of key identifiers.

For Arm platform Implementation, there MUST be only two types of arrays, corresponding to the provisioning lifecycle stage:

1. Chip Manufacturing array - known as "CM"

2. Device Manufacturing array - known as "DM"

In Arm platform Implementation, for a particular type of array, the maximum number of array entries SHALL be 8, while the maximum entries in a single array SHALL be 6.

Arm Platform public key identifiers are encoded in a CoMID using Reference Value triples.

Each array entry is encoded in a single Reference Value Triple.

Each public key identifier is encoded in a single `measurement-map`.

1. `mkey` uniquely identifies the position of each key identifier, using the text variant of `$measured-element-type-choice`.
The encoding follows a consistent pattern: the prefix "arm.platform.rotpk", followed by the set name ("CM" or "DM"), and finally the entry position within the active array (starting from zero).
The parts are separated by `"."`.
`mkey` is aligned to the elements received in the TBB RoTPK claim from the Arm Platform evidence.

For example, to encode a "CM" key identifier at active position 3, `mkey` will be set to "arm.platform.rotpk.CM.3".


2. The public key identifier is encoded using cryptokeys (key 13). The array MUST have only one entry encoded using the `tagged-bytes` variant of the `$crypto-key-type-choice`.
The length of the `tagged-bytes` MUST be 32, 48 or 64 bytes.

3. The `authorized-by` field of the `measurement-map` MUST NOT be present.

Find the related CDDL definition of Measurement Values Map in {{cddl-rotpk-mvm}} and the associated measurement map in {{cddl-rotpk-mm}}.

~~~ cddl
arm-rotpk-measurement-values-map = {
  &(cryptokeys: 13) => [ arm-rotpk-id ]
}

arm-hash-type = bytes .size 32 / bytes .size 48 / bytes .size 64

arm-rotpk-id = #6.560(arm-hash-type)
~~~
{: #cddl-rotpk-mvm title="Arm Platform ROTPK measurement-values-map"}

~~~ cddl
arm-rotpk-measurement-map = {
  &(mkey: 0) => text .regexp "arm.platform.rotpk.[CD]M\\.[0-5]"
  &(mval: 1) => arm-rotpk-measurement-values-map
}
~~~
{: #cddl-rotpk-mm title="Arm Platform ROTPK measurement-map"}


An Endorser may choose to provision either the entire set of entries or the single active entry currently in use on the platform.

#### Arm Platform Manufacturing Configuration

The Arm Platform Manufacturing Configuration represents a record of production phases and testing conducted during the manufacturing process for the platform instance.

Arm Platform Manufacturing Configuration is vendor-specific variable-length data.

It is represented in a `raw-value` of the `measurement-values-map`, using the `tagged-masked-raw-value` variant of the `$raw-values-type-choice`.
Refer to {{Section 5.1.4.1.4.6 of -rats-corim}} for the details about the comparison algorithm.

~~~ cddl
arm-manufacturing-config-measurement-values-map = {
  &(raw-value: 4) => arm-tagged-masked-raw-value
}

arm-config-tagged-masked-raw-value = #6.563([
  value: bytes
  mask: bytes
])
~~~
{: #cddl-mfg-config-mvm title="Arm Platform Manufacturing Configuration measurement-values-map"}

The `measurement-values-map` for an Arm Platform manufacturing configuration is wrapped in a `measurement-map` with an `mkey` using the text variant of the `$measured-element-type-choice`.
The value of the `mkey` MUST be "arm.platform.platform-manufacturing-config".
There MUST be only one `measurement-map` with `mkey` "cca.platform-manufacturing-config" in the triple.

The `authorized-by` field of the `measurement-map` MUST NOT be present.

Find the related CDDL definitions in  {{cddl-mfg-config-mvm}} and in {{cddl-mfg-config-mm}}.

~~~ cddl
arm-config-measurement-map = {
  &(mkey: 0) => "arm.platform.platform-manufacturing-config"
  &(mval: 1) => arm-manufacturing-config-measurement-values-map
}
~~~
{: #cddl-mfg-config-mm title="Arm Platform Manufacturing Configuration measurement-map"}

#### CoMID Example

An example CoMID containing one Reference Values triple with the expected values for both software components and platform configuration is given in {{ex-arm-platform-refval}}.

~~~ cbor-diag
{::include examples/platform-refval-meas.diag}
~~~
{: #ex-arm-platform-refval title="Example CCA Platform Reference Values" }

### Attestation Verification Keys {#sec-keys}

An Attestation Verification Key contains the public key associated with the Arm Platform Attestation Key (CPAK).
When appraising Platform Evidence, the Verifier uses the Implementation ID and Instance ID claims found in the Platform Token to identify the key that it shall use to verify the signature on the Arm Platform token.
This allows the Verifier to prove (or disprove) the Attester's claimed identity.

Each verification key is provided with the corresponding Arm Platform Instance and Implementation IDs in an `attest-key-triple-record`.
Specifically:

* The Instance and Implementation IDs are encoded in the `environment-map` as described in {{sec-arm-rot-id}};
* The CPAK public key uses the `tagged-pkix-base64-key-type` variant of the `$crypto-key-type-choice`.

The CPAK public key is a SubjectPublicKeyInfo {{-pkix-x509}} using the encoding defined in {{Section 13 of -pem}}.
There MUST be only one key in an `attest-key-triple-record`.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
