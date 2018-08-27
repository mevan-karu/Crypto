# Crypto
Sample application to provide cryptographic operations using a HSM.

This application is under development. Currently supported mechanisms are follows,
  1. Key Generation 
     1. AES key generation.
     2. RSA key pair generation.
  2. Encryption -
     1. AES encryption.
     2. RSA encryption.
  3. Decryption -
     1. AES decryption.
     2. RSA decryption.

First you need to add **IAIK PKCS #11 wrapper** to your project as a dependency. You can find the way to do it in following [blog](https://medium.com/@mevan.karu/want-to-know-how-to-talk-to-a-hsm-at-code-level-69cb9ba7b392).


Configure **pkcs11Sample.properties** file as required and rename the file to **pkcs11.protperties**.
