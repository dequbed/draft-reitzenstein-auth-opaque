---
title: "A SASL and GSS-API Mechanism using the asymmetric password-authenticated key agreement OPAQUE"
abbrev: "OPAQUE Authentication"
docname: draft-reitzenstein-kitten-opaque-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes

submissiontype: independent
number:
consensus: false
v: 3
area: AREA
workgroup: WG Working Group

author:
  -
    ins: N. von Reitzenstein Čerpnjak
    fullname: Nadja von Reitzenstein Čerpnjak
    email: me@dequbed.space

normative:
  RFC5801:
  RFC5802:
  RFC5234:
  RFC3629:
  RFC9106:
  RFC9266:

  OPAQUE:
    target: https://github.com/cfrg/draft-irtf-cfrg-opaque
    title: The OPAQUE Asymmetric PAKE Protocol
    author:
     -
        ins: D. Bourdrez
        name: Daniel Bourdrez
     -
        ins: H. Krawczyk
        name: Hugo Krawczyk
        organization: Algorand Foundation
     -
        ins: K. Lewi
        name: Kevin Lewi
        organization: Novi Research
     -
        ins: C. A. Wood
        name: Christopher A. Wood
        organization: Cloudflare, Inc.
    date: 2023-01-12
    format:
      HTML: https://cfrg.github.io/draft-irtf-cfrg-opaque/draft-irtf-cfrg-opaque.html
    refcontent: Work in Progress
    seriesinfo:
        I-D: draft-irtf-cfrg-opaque-latest

  I-D.irtf-cfrg-voprf-17: VOPRF

informative:
  TripleHandshake:
    target: https://www.mitls.org/pages/attacks/3SHAKE
    title: "Triple Handshakes and Cookie Cutters: Breaking and Fixing Authentication over TLS"
    author:
      -
        ins: K. Bhargavan
        name: Karthikeyan Bhargavan
        organization: INRIA Paris-Rocqencourt
      -
        ins: A. Delignat-Lavaud
        name: Antoine Delignat-Lavaud
        organization: INRIA Paris-Rocqencourt
      -
        ins: C. Fournet
        name: Cédric Fournet
        organization: Microsoft Research
      -
        ins: A. Pironti
        name: Alfredo Pironti
        organization: INRIA Paris-Rocqencourt
      -
        ins: P. Strub
        name: Pierre-Yves Strub
        organization: IMDEA Software Institute
    date: 2014-05
    format:
      PDF: https://www.mitls.org/downloads/tlsauth.pdf
    refcontent: miTLS

--- abstract

This specification describes a Simple Authentication and Security Layer (SASL, RFC4422) authentication mechanisms based on the OPAQUE asymmetric password-authenticated key agreement (PAKE) protocol.

The mechanism offers two distinct advantages over the SCRAM family of mechanisms. The underlying OPAQUE protocol provides the ability for clients to register without the server having to have access to the clear text password of an user, preventing password exfiltration at registration. Secondly a successful authentication produces a long-term secret key specific to the user that can be used to access encrypted server-side data without needing to share keys between clients via side-band mechanisms.

When used in combination with TLS or an equivalent security layer these mechanisms allow for secure channel binding.

--- middle

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Introduction

This specification describes an authentication mechanism called OPAQUE, based on the asymmetric PAKE of the same name. The mechanisms provide strong mutual authentication and allow binding the authentication to an pre-existing underlying encrypted transport.

The mechanism specified in this document is a Simple Authentication and Security Layer (SASL) mechanism compatible to the bridge between SASL and the Generic Security Services Application Programming Interface (GSS-API) called "GS2" {{RFC5801}}. This means that the mechanism can be used as either a SASL mechanism or a GSS-API mechanism.

The OPAQUE algorithm provides the following features which this mechanism makes use of:

- The authentication information stored in an authentication database on the server is not sufficient to impersonate the client. It is additionally salted and bound to a private key of the server, making pre-stored dictionary attack impossible.
- Successful authentication does not grant the server enough information to impersonate the client.
- Mutual authentication is implicit and required. A successful authentication always strongly authenticates both sides of the exchange.
- A successful authentication provides both parties with an ephemeral shared secret. This secret has high entropy and can be used to establish a trusted encrypted channel without deriving trust from a 3rd party.
- A successful authentication additionally provides the client with a constant secret. This secret is only known to the client and the same for every authentication. It can be used to e.g. store encrypted data on the server without having to manage keys locally.

# OPAQUE Algorithm Overview

The Authenticated Key Exchange defined by OPAQUE consists of three messages — KE1, KE2 and KE3 — send by the client (KE1, KE3) and server (KE2) respectively. A client knows the outcome of the authentication after receiving KE2, the server after receiving KE3.

The following is a description of a full SASL OPAQUE-A255SHA authentication exchange. Nothing in OPAQUE-A255SHA prevents sending the first client response with the SASL authentication request as defined by an application protocol ("initial client response"). See {{RFC4422}} for more details.

The OPAQUE client starts by being in possession of an username and password. It uses the password to generate a KE1, and sends this message and the username to the server.

The server retrieves the corresponding authentication information, i.e. registration record, OPRF seed, server private key, and the key-stretching function (KSF) parameters that were used at registration. It uses the first three to generate a KE2 message as per {{OPAQUE}} and sends that, channel binding data (if any) and the KSF parameters to the client.

The client authenticates the server using KE2 and the KSF parameters, also showing the integrity of the channel binding data in the process, and generates a final KE3 message it can return to the server.

The three messages KE1, KE2 and KE3 are generated using the following functions specified in {{OPAQUE}} with the configuration specified in Section {{<opaque-3dh-configuration-for-opaque-a255sha-plus}}:

    KE1 := ClientInit(password)

    KE2 := ServerInit(
             server_identity, server_private_key, server_public_key,
             record, credential_identifier, oprf_seed, KE1, client_identity
           )

    KE3 := ClientFinish(client_identity, server_identity, KE2)

The values of `client_identity` and `server_identity` are set to the byte sequences:

    client_identity := client-first-message + "," + client_public_key

    server_identity := server-message-bare + "," + server_public_key

With the values and encodings of the remaining parameters per the OPAQUE specification, `client_`- and `server_public_key` being encoded as raw bytes, and `+` indicating concatenation.

Upon receipt of KE3 the server can validate the authentication exchange including integrity of the channel binding data it sent previously, and extract a session key that strongly authenticates the client to the server.

# OPAQUE Mechanism Name

The name of the mechanism specified in this document is "OPAQUE-A255SHA" or "OPAQUE-A255SHA-PLUS" respectively. The "-PLUS" suffix is only used when the authenticating parties support and intent to use channel binding. If the server supports channel binding it SHOULD advertise both the bare and the plus version of this mechanism. If the server does not it will only advertise the bare version.

# OPAQUE-3DH configuration for OPAQUE-A255SHA(-PLUS)

The OPAQUE-3DH configuration according to Section 7 of {{OPAQUE}} used by the OPAQUE-A255SHA mechanism is made up of the following cryptographic primitives:

- OPRF(ristretto255, SHA-512) as specified in {{Section 4.1 of -VOPRF}}
- HKDF {{!RFC5869}} using SHA-512 as KDF
- HMAC {{!RFC2104}} using SHA-512 as MAC
- SHA-512 as Hash
- Argon2id {{RFC9106}} as KSF, with the remaining parameters being set during an authentication exchange
- The same ristretto255 group used by the OPRF as Group
- The ASCII-String "SASL-OPAQUE-A255SHA" as Context

Implementations of this mechanism SHOULD default to Argon2id parameters of (t=1, p=4, m=2^21).

# OPAQUE Authentication Exchange

An example of an OPAQUE-A255SHA authentication exchange consisting of three messages, send by the client, server and client respectively:

<!-- TODO: replace ke1, ke2 & ke3 with values -->

    C: n,,n=user,r=<ke1>
    S: c=biws,i=bT0yMDk3MTUyLHQ9MSxwPTQ=,v=<ke2>
    C: p=<ke3>

First, the client sends the "client-first-message" containing:

- A GS2 header consisting of a flag indicating channel binding support and usage, and an optional SASL authorization identity.
- The authentication ID (AuthID) of the user.
- OPAQUE KE1, containing the OPRF credential request, a nonce, and an ephemeral public key.

In response the server sends the "server-message" containing:

- An encoding of requested channel binding data
- Parameters for the KSF that needs to be used by the client
- OPAQUE KE2, containing the OPRF credential response, a nonce, and an ephemeral public key.
- A MAC proving the integrity of the exchange so far and cryptographically authenticating the server to the client (also contained in KE2)

The client then recovers a client-only export key and a shared secret specific to this session from the OPRF response using the defined KSF with the user-provided password and parameters sent by the server.

To finalize the authentication a client sends a "client-final-message" containing itself a MAC over the exchange (in KE3), thus cryptographically authenticating the client to the server.

## OPAQUE Attributes

This section details all attributes permissible in messages, their use and their value format. All Attribute keys are a single US-ASCII letter and case-sensitive. The selection of letters used for attribute keys is based on SCRAM {{RFC5802}} to make it easier to adapt extensions defined for SCRAM to this mechanism.

The order of attributes is fixed for all messages, except for extension attributes which are limited to designated positions but may appear in any order. Implementations MUST NOT assume a specific ordering of extensions.

- a: This is an optional attribute and is part of the GS2 {{RFC5801}} bridge between GSS-API and SASL. Its specification and usage is the same as defined in {{RFC5802, Section 5.1}}.

- n: This attribute specifies the name of the user whose password is used for authentication (aka "authentication identity" {{!RFC4422}}). Its encoding, preparation, and usage is the same as defined in {{RFC5802, Section 5.1}}.

- m: This attribute is reserved for future extensibility. In this version of OPAQUE its presence in a client or server message MUST cause authentication failure when the attribute is parsed by the other end.

- r: This attribute specifies a base64-encoded serialization of the KE1 message as specified by {{OPAQUE}}.

- c: This REQUIRED attribute specifies the base64-encoded GS2 header and channel binding data. Its specification is the same as defined in {{RFC5802, Section 5.1}}, however it is sent by the server to the client instead of the other way around as in SCRAM.

- i: This attribute specifies base64-encoded parameters for the KSF to be used. The format of the parameters is specific in Section {{<ksf-parameter-encoding}}.

- v: This attribute specifies a base64-encoded serialization of the KE2 message as specified by {{OPAQUE}}.

- p: This attribute specifies a base64-encoded serialization of the KE3 message as specified by {{OPAQUE}}.

- Further as of now unspecified mandatory and optional extensions. Mandatory extensions are encoded using the "m" attribute, optional attributes may use any unassigned attribute name. Unknown optional attributes MUST be ignored upon receipt.

### KSF parameter encoding

The Argon2id {{RFC9106}} algorithm as used by OPAQUE-A255SHA requires the three parameters t, p, and m to be additionally transferred from server to client for an authentication exchange. The values for these parameters are fixed at registration time, but may be different for each user.

[^1]

The limits and interpretation of the parameters set in {{RFC9106}} apply. Parameters are encoded as a sequence of ASCII key-value pairs separated by ASCII commas. The key and value in each pair are separated by a single ASCII equals sign ('='). The keys for the parameters are the single letter identifiers assigned by {{RFC9106}}, the values are encoded as decimal numbers with no digit delimiters or separators.

Example of the encoding of the parameters number of passes = 1, degree of parallelism = 4 and memory size = 2 GiB (i.e. 2^21 KiB) using the above rules:

    m=2097152,t=1,p=4

[^1]: Note: Argon2 may get a PKCS#5 parameter encoding, e.g. [](https://github.com/P-H-C/phc-winner-argon2/issues/348) ; should we wait on that or specify our own format?
{:nadja}

## SASL Mechanism Requirements

This section describes the required information for SASL mechanisms as laid out in {{RFC4422, Section 5}}.

1) "OPAQUE-A255SHA" and "OPAQUE-A255SHA-PLUS"

2a) OPAQUE is a client-first mechanism

2b) OPAQUE does not send any additional data to indicate a successful outcome. All authentication exchanges take 3 messages regardless of success.

3) OPAQUE can transfer authorization identities from the client to the server.

4) OPAQUE does not offer security layers but allows channel binding.

5) OPAQUE uses a MAC to protect the integrity of the entire authentication exchange including the authzid.

# Channel Binding

OPAQUE supports binding the authentication to an underlying secure transport. Support for channel binding is optional, therefore the usage of channel binding is negotiable.

The negotiation of channel binding is performed as defined in {{RFC5802, Section 6}} with the following differences:

- The non-PLUS and PLUS variants of the mechanism are instead named OPAQUE-&lt;variant&gt; and OPAQUE-&lt;variant&gt;-PLUS respectively.

- As it is the server who sends the channel binding data the client is responsible to verify this data by constructing the expected value of the "c=" attribute and comparing it to the received one. This comparison SHOULD be implemented to be constant-time.

## Default Channel Binding

'tls-exporter' is the default channel binding type for any application that do not specify one.

Servers MUST implement the 'tls-exporter' {{RFC9266}} channel binding type if they implement any channel binding and make use of TLS-1.3 {{!RFC8446}}. Clients SHOULD implement the 'tls-exporter' {{RFC9266}} channel binding type if they implement any channel binding and make use of TLS-1.3.

Server and clients SHOULD implement the 'tls-unique' {{!RFC5929}} channel binding if they implement channel binding and make use of TLS-1.2. If a server or client implements 'tls-unique' they MUST ensure appropriate protection from the {{TripleHandshake}} vulnerability using e.g. the Extended Master Secret Extension {{!RFC7627}}.

Servers MUST use the channel binding type indicated by the client, or fail authentication if they do not support it.

# Formal Syntax

The following syntax specification is written in Augmented Backus-Naur Form (ABNF) notation as specified in {{RFC5234}}. The non-terminals "UTF8-2", "UTF8-3" and "UTF8-4" are defined in {{RFC3629}}.

The syntax is based in large parts on {{RFC5802, Section 7}}, which may be referenced for clarification. If this specification and {{RFC5802}} are in conflict, this specification takes priority.

Used definitions from {{RFC5802}} are reproduced here for convenience:


    ALPHA = <as defined in RFC 5234 appendix B.1>
    DIGIT = <as defined in RFC 5234 appendix B.1>
    UTF8-2 = <as defined in RFC 3629 (STD 63)>
    UTF8-3 = <as defined in RFC 3629 (STD 63)>
    UTF8-4 = <as defined in RFC 3629 (STD 63)>

    attr-val        = ALPHA "=" value
                     ;; Generic syntax of any attribute sent
                     ;; by server or client

    value           = 1*value-char

    value-safe-char = %x01-2B / %x2D-3C / %x3E-7F /
                     UTF8-2 / UTF8-3 / UTF8-4
                     ;; UTF8-char except NUL, "=", and ",".

    value-char      = value-safe-char / "="

    printable       = %x21-2B / %x2D-7E
                     ;; Printable ASCII except ",".
                     ;; Note that any "printable" is also
                     ;; a valid "value".

    base64-char     = ALPHA / DIGIT / "/" / "+"

    base64-4        = 4base64-char

    base64-3        = 3base64-char "="

    base64-2        = 2base64-char "=="

    base64          = *base64-4 [base64-3 / base64-2]

    posit-number    = %x31-39 *DIGIT
                     ;; A positive number.

    saslname        = 1*(value-safe-char / "=2C" / "=3D")
                     ;; Conforms to <value>.

    authzid         = "a=" saslname
                     ;; Protocol specific.

    cb-name         = 1*(ALPHA / DIGIT / "." / "-")
                      ;; See RFC 5056, Section 7.
                      ;; E.g., "tls-server-end-point" or
                      ;; "tls-unique".

    gs2-cbind-flag  = ("p=" cb-name) / "n" / "y"
                      ;; "n" -> client doesn't support channel binding.
                      ;; "y" -> client does support channel binding
                      ;;        but thinks the server does not.
                      ;; "p" -> client requires channel binding.
                      ;; The selected channel binding follows "p=".

    gs2-header      = gs2-cbind-flag "," [ authzid ] ","
                      ;; GS2 header for OPAQUE

    username        = "n=" saslname
                      ;; Usernames are prepared using SASLprep.

    reserved-mext   = "m=" 1*(value-char)
                      ;; Reserved for signaling mandatory extensions.
                      ;; The exact syntax will be defined in
                      ;; the future.

    channel-binding = "c=" base64
                      ;; base64 encoding of cbind-input.

    cbind-data      = 1*OCTET

    cbind-input     = gs2-header [ cbind-data ]
                      ;; cbind-data MUST be present for
                      ;; gs2-cbind-flag of "p" and MUST be absent
                      ;; for "y" or "n".

The following definitions are specific to OPAQUE:

    ke1             = "r=" base64
                      ;; base64 encoding of the OPAQUE KE1 message struct
    ke2             = "v=" base64
                      ;; base64 encoding of the OPAQUE KE2 message struct
    ke3             = "p=" base64
                      ;; base64 encoding of the OPAQUE KE3 message struct

    ksf-params      = "i=" base64
                      ;; base64 encoding of KSF parameters

    client-first-message-bare =
                [reserved-mext ","] username "," ke1 ["," extensions]

    client-first-message =
                gs2-header client-first-message-bare

    server-message-bare =
                [reserved-mext ","] channel-binding "," ksf-params
                ["," extensions]

    server-message  = server-message-bare "," ke2

    client-final-message = ke3

# Security Considerations

The KSF parameters and channel bindings aren't authenticated before KSF usage, allowing a DoS of a client by an malicious actor posing as the server, as it can send excessively expensive KSF parameters.

If not used with a secure channel providing confidentiality this mechanism leaks the authid and authzid of an authenticating user to any passive observer.

The cryptographic security of this mechanism is not increased over the one provided by the underlying OPAQUE protocol, so all security considerations listed in the {{OPAQUE}} specification also apply to this one.

# Open Issues

- With the current design the KSF parameters can not be MAC-verified until after they have been used. This is bad. The only other option is using the ephemeral keypair to generate a MAC key and use that. This may impact security.

- This mechanism should be extended to also become a GSS-API mechanism like SCRAM is.

# IANA Considerations

A future revision of this document will request a new registry for the OPAQUE family of SASL mechanism, outlining all required details on the primitives used by the 'OPAQUE-A255SHA' variant.

--- back

# Acknowledgments
{:numbered="false"}

Thank you to Daniel Bourdrez, Hugo Krawczyk, Kevin Lewi, and C. A. Wood for their work on the OPAQUE PAKE that this mechanism is based on.
Thank you to Abhijit Menon-Sen, Alexey Melnikov, Nicolás Williams, and Chris Newman for their work on the SCRAM RFC, most of which this draft oh so blatanly steals for its own gain.

{:nadja: source="Nadja"}
