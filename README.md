# Attribute-based Encryption
This library includes toy implementation of the following algorithms:
* [GPSW06](https://eprint.iacr.org/2006/309) (Under evaluation) : Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data
* [BSW07](https://hal.archives-ouvertes.fr/hal-01788815/document) : Ciphertext-Policy Attribute-Based Encryption
    * Implementation detail: Type A pairing is used.
    * `f = g^(1/b)` is moved to secret key structure, coz encryption does not need the delegation.

*Note: This library is not production ready. DO NOT USE IN PRODUCTION.*