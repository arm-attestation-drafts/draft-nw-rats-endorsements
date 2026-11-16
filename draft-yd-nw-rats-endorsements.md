---
title: "A CoRIM Profile for Arm's Normal World Attestation Endorsements"
abbrev: "Arm NW Endorsements"
docname: draft-yd-nw-rats-endorsements-latest
category: info

date: {DATE}
category: info
ipr: trust200902
area: Security
workgroup: RATS

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

Arm Normal World Attestation Endorsements comprise reference values and cryptographic key material that a Verifier needs to appraise Attestation Evidence produced from Normal World running on an Arm Platform.

This memo defines Normal World Endorsements as a profile of the CoRIM data model.


--- middle

# Introduction

Arm's Normal World Remote Attestation provides a mechanism for a Normal World application to obtain a Remote Attestation token from the underlying Arm platform.

Arm's Normal World Endorsements comprise reference values and cryptographic key material that a Verifier needs to appraise Attestation Evidence produced by an Arm platform that provides the neccessary attestation services to an application operating in the Normal World.

This memo defines Normal World Endorsements as a profile of the CoRIM data model {{-rats-corim}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The reader is assumed to be familiar with the terms and concepts introduced in {{Section 4 of -rats-arch}}.

## Arm Platform Endorsements


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.