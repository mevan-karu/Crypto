# Crypto
Sample application to provide cryptographic operations using a HSM.

This application is under development. Currently supported mechanisms are follows,
  1. Key Generation 
     1. AES key generation.
     2. RSA key pair generation.
  2. Encryption
     1. AES encryption.
     2. RSA encryption.
  3. Decryption
     1. AES decryption.
     2. RSA decryption.
  4. Full Sign/Verify
     1. RSA SHA-1
     2. RSA SHA-256
     3. RSA SHA-384
     4. RSA SHA-512
     5. RSA MD5
  5. Digesting
     1. SHA-1
     2. SHA-256
     3. SHA-384
     4. SHA-512
     5. MD5

You can use the Utimaco simulator for testing purposes. Refer to this [blog](https://medium.com/@mevan.karu/you-dont-need-to-buy-a-hsm-to-see-how-it-works-2bf201f39d83) for simulator configurations.

You need to add **IAIK PKCS #11 wrapper** to your project as a dependency. You can find the way to do it in following [blog](https://medium.com/@mevan.karu/want-to-know-how-to-talk-to-a-hsm-at-code-level-69cb9ba7b392).

Configure **pkcs11Sample.properties** file as required and rename the file to **pkcs11.protperties**.
