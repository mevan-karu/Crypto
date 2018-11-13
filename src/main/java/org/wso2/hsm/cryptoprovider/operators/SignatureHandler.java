package org.wso2.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;

public class SignatureHandler {

    /**
     * Constructor for signature handler.
     */
    public SignatureHandler() {

    }

    /**
     * Method to sign a given data.
     *
     * @param session       : Session used to perform signing.
     * @param dataToSign    : Data to be signed.
     * @param signMechanism : Signing mechanism
     * @param signKey       : Key used for signing.
     * @return signature as a byte array.
     * @throws TokenException
     */
    public byte[] sign(Session session, byte[] dataToSign, Mechanism signMechanism, PrivateKey signKey) {

        byte[] signature = null;
        if (signMechanism.isFullSignVerifyMechanism() ||
                signMechanism.isSingleOperationSignVerifyMechanism()) {
            try {
                session.signInit(signMechanism, signKey);
                signature = session.sign(dataToSign);
            } catch (TokenException e) {
                System.out.println("Full sign generation error : " + e.getMessage());
            }
        }
        return signature;
    }

    /**
     * Method to verify a given data.
     *
     * @param session         : Session used to perform verifying.
     * @param dataToVerify    : Data to be verified.
     * @param signature       : Signature of the data.
     * @param verifyMechanism : verifying mechanism.
     * @param verificationKey : Key used for verification.
     * @return True if verified.
     */
    public boolean verify(Session session, byte[] dataToVerify, byte[] signature,
                          Mechanism verifyMechanism, PublicKey verificationKey) {

        boolean verified = false;
        if (verifyMechanism.isFullSignVerifyMechanism()) {
            try {
                session.verifyInit(verifyMechanism, verificationKey);
                session.verify(dataToVerify, signature);
                verified = true;
            } catch (TokenException e) {
                if (!e.getMessage().equals("")) {
                    System.out.println("Sign verification error : " + e.getMessage());
                }
            }
        }
        return verified;
    }
}
