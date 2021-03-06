Predicate Based Encryption Library
==================================

                                                ____  _____ ____  _____ _
                                    _ __  _   _|  _ \| ____| __ )| ____| |
                                   | '_ \| | | | |_) |  _| |  _ \|  _| | |
                                   | |_) | |_| |  __/| |___| |_) | |___| |___
                                   | .__/ \__, |_|   |_____|____/|_____|_____|
                                   |_|    |___/

The Predicate Based Encryption Library (Pebel) is a simple python 3.x
module that provides 'default' implementations for the use of the IBE,
ABE, and PBE family of asymmetric encryption schemes within python
scripts and modules.

## Overview

This module has been designed to facilitate the ease of use of several
advanced crypto schemes within python scripts and modules. For each
supported scheme an API has been provided that allows for key
generation, encryption and decryption operations.

Based upon the Charm and pyCrypto modules the underlying cryptographic
operations follow the standard KEM/DEM setup. The plaintext is
encrypted using a symmetric cipher (AES 256) and a randomly generated
session key is encrypted using the advanced crypto-scheme.

## Predicate Based Encryption

__Predicate Based Encryption__ (PBE) is a family of novel and modern
asymmetric encryption schemes in which the decryption of a cipher-text
is dependent upon the satisfaction of a boolean predicate (access
policy) by a set of attributes. This allows for expressive and
fine-grained access control to be specified over cipher-texts. Namely
PBE schemes allow for Encrypted __Attribute Based Access Control__
(ABAC) to be implemented efficiently.

There are two main types of PBE Scheme.

The first __Ciphertext-Policy__ (CP) is when data is encrypted under a
boolean predicate, and decryption keys are constructed from sets of
attributes. This directly mimics the access control provided by ABAC.

The second __Key-Policy__ (KP), is when data is encrypted under a set of
attributes, and decryption keys are constructed from a set of
attributes. This allows for capability based access control and is
useful for providing keyword encrypted search over encrypted data.

## Supported Schemes

Currently there is support for:

* Ciphertext-Policy Attribute Based Encryption :: based upon the
     implementation of
     [Bethencourt2007cae](http://dx.doi.org/10.1109/SP.2007.11)
     provided by the Charm toolkit.
* Key-Policy Attribute Based Encryption :: based upon the
     implementation of
     [Lewko2008rsw](http://dx.doi.org/10.1109/SP.2010.23) provided by
     the Charm toolkit.

For each schemes presented, there will be four provide functions:

 1. <name>_setup :: Initialises the crypto-scheme and generates the
    master public and private keys.

 2. <name>_keygen :: Uses the master keys to generate decryption keys.

 3. <name>_encrypt :: Encrypts a plaintext byte array from either an
    io file descriptor in 'b' mode, or byte stream, under the provided
    encryption key.

 4. <name>_decrypt :: Attempts to decrypts a ciphertext byte array
    from either an io file descriptor in 'b' mode, or byte stream,
    using the provided decryption key. If decryption is successful the
    plaintext is returned. If not an L{PebelDecryptionException} is
    raised.

The function parameters will differ according to the schemes. Please
see each modules documentation for more details.

Along side these wrapper functions are a series of python scripts that
can be called from the commmand line to encrypt files to allow
experimentation with PBE schemes. For each supported scheme a script
is provided per function.

_Note:_ Only simple access policies and attributes can be specified
 within these schemes. Support for numerical attributes is not there
 yet.


## Documentation

Installation instructions can be found within INSTALL.

API documentation can be generated by running doxygen with the doxypy extension

Developer/User documentation, when completed, will be found within the
docs folder. In the meantime example deployable scripts can be found
within =bin=, and example shell commands in =doc/sample-innvocation.sh=

## Resources


* Charm http://www.charm-crypto.com/
* pyCrypto  http://www.pycrypto.org/
