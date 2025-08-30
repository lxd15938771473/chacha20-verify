# Formal Verification of ChaCha20-Poly1305 in openHiTLS
This is the source code repo for our project, which conducts the equvalence verfication of ChaCha20：
1) described in the standard (RFC 8439), and
2) implemented in the openHiTLS (v3.0.10).

This instruction describes the organization of the source code and how to use it.

## Software Requirements
- To run the RFC and openHiTLS Cryptol formal model of TLS 1.3 state machine you need [cryptol 3.1.0+](https://cryptol.net/).
- To verify equivalence between the openHiTLS formal model and the C code implementations, you need [SAW](https://saw.galois.com/).

## File Organization
**Source code files**:

- ChaCha20 Model, in the directory ``chacha20/``
  - ``chacha_combined.c``  : Defined the source code of ChaCha20 algorithm in openHiTLS
  - ``chacha_combined.bc`` : Compiled bytecode from openHiTLS ChaCha20 algorithm source code
  - ``chacha_openHiTLS.cry`` :  Defined the ChaCha20 Cryptol model based on OpneSSL source code
  - ``chacha_rfc.cry`` : Defined the ChaCha20 Cryptol model based on RFC standard document 
  - ``chacha.saw``: The script for verifying the equvalence between openHiTLS Cryptol models and ChaCha20 C code implementations
  - ``chacha_property.cry``: Proved the ChaCha20 equvalence and some security properties between the Cryptol model based on openHiTLS and the Cryptol model based on standard documentation


## The Execution of RFC Model Alone
You can use the following commands to run the RFC Cryptol model once in the console for revision and testing.

```
PROJECTROOTDIR> Cryptol
PROJECTROOTDIR> :l chacha_rfc.cry
encrypt: PROJECTROOTDIR> ChaCha20Encrypt k i n msg
```

## The Execution of openHiTLS Model Alone
You can use the following commands to run the openHiTLS Cryptol model once in the console for revision and testing.

```
PROJECTROOTDIR> Cryptol
PROJECTROOTDIR> :l chacha_openhitls.cry / :l chacha_block.cry 
encrypt: PROJECTROOTDIR> :l chacha_property.cry 
PROJECTROOTDIR> CHACHA20_ENC k i n msg
```

## The Execution of SAW
You can use the following commands to run the SAWScript to verify the equvalence between openHiTLS formal models and C code implementations, and output the results to the terminal.
```
PROJECTROOTDIR> saw [filename].saw
```
