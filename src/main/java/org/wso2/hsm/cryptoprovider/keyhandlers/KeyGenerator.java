package org.wso2.hsm.cryptoprovider.keyhandlers;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import sun.security.pkcs11.wrapper.PKCS11Constants;

public class KeyGenerator {

    private static KeyGenerator keyGenerator;

    /**
     * Singleton pattern is used and only one KeyGenerator instance will be used.
     *
     * @return KeyGenerator instance
     */
    public static KeyGenerator getKeyGenerator() {
        if (keyGenerator == null) {
            keyGenerator = new KeyGenerator();
        }
        return keyGenerator;
    }

    private KeyGenerator() {
    }

    /**
     * Method to generate RSA key pair.
     *
     * @param generationMechanism : long value of key generation mechanism
     * @param privateKeyTemplate  : Template of the generated private key
     * @param publicKeyTemplate   : Template of the generated private key
     * @return True if pair of keys generated, else False.
     * @throws TokenException : returns if exception occurred in the Token.
     */
    public boolean generateRSAKeyPair(Session session, long generationMechanism, RSAPrivateKey privateKeyTemplate,
                                      RSAPublicKey publicKeyTemplate) {
        boolean generated = false;
        MechanismInfo mechanismInfo = null;
        Mechanism keyPairGenerationMechanism = null;
        try {
            if (generationMechanism == PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN) {
                mechanismInfo = session.getToken().getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS));
                keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
            } else if (generationMechanism == PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN) {
                mechanismInfo = session.getToken().getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS));
                keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN);
            }
            if ((keyPairGenerationMechanism != null) && (mechanismInfo != null)) {

                privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
                privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
                privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);

                publicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);

                publicKeyTemplate.getVerify()
                        .setBooleanValue(mechanismInfo.isVerify());
                publicKeyTemplate.getVerifyRecover()
                        .setBooleanValue(mechanismInfo.isVerifyRecover());
                publicKeyTemplate.getEncrypt()
                        .setBooleanValue(mechanismInfo.isEncrypt());
                publicKeyTemplate.getDerive()
                        .setBooleanValue(mechanismInfo.isDerive());
                publicKeyTemplate.getWrap()
                        .setBooleanValue(mechanismInfo.isWrap());

                privateKeyTemplate.getSign()
                        .setBooleanValue(mechanismInfo.isSign());
                privateKeyTemplate.getSignRecover()
                        .setBooleanValue(mechanismInfo.isSignRecover());
                privateKeyTemplate.getDecrypt()
                        .setBooleanValue(mechanismInfo.isDecrypt());
                privateKeyTemplate.getDerive()
                        .setBooleanValue(mechanismInfo.isDerive());
                privateKeyTemplate.getUnwrap()
                        .setBooleanValue(mechanismInfo.isUnwrap());
                session.generateKeyPair(keyPairGenerationMechanism, publicKeyTemplate, privateKeyTemplate);
                generated = true;
            }
        } catch (TokenException e) {
            System.out.println("RSA key pair generation error : " + e.getMessage());
        }
        return generated;
    }

    /**
     * Method to generate AES key.
     *
     * @param session           : Session to
     * @param secretKeyTemplate : Template of the secret key to be generated.
     * @return True if key is generated.
     */
    public boolean generateAESKey(Session session, AESSecretKey secretKeyTemplate) {
        boolean generated = false;
        Mechanism keyMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
        secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
        secretKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
        try {
            session.generateKey(keyMechanism, secretKeyTemplate);
            generated = true;
        } catch (TokenException e) {
            System.out.println("AES key generation error : " + e.getMessage());
        }
        return generated;
    }


}
