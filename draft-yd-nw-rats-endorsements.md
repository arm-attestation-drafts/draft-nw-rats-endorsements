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

### Arm Platform Endorsements linkage to Arm Platform {#sec-cca-rot-id}

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


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
