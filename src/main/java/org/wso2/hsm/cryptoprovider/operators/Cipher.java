package org.wso2.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;

public class Cipher {

    public Cipher() {
    }

    public byte[] encryptAES(Session session, byte[] dataToBeEncrypted,
                             AESSecretKey encryptionKey, byte[] encryptInitializationVector,
                             long encryptingMechanism) throws TokenException {
        Mechanism encryptionMechanism = Mechanism.get(encryptingMechanism);
        InitializationVectorParameters encryptInitializationVectorParameters = new InitializationVectorParameters(encryptInitializationVector);
        encryptionMechanism.setParameters(encryptInitializationVectorParameters);
        session.encryptInit(encryptionMechanism, encryptionKey);
        byte[] encryptedData = session.encrypt(dataToBeEncrypted);
        return encryptedData;
    }

    public byte[] decryptAES(Session session, byte[] dataToBeDecrypted,
                             AESSecretKey decryptionKey, long decryptingMechanism,
                             byte[] decryptionInitializationVector) throws TokenException {
        Mechanism decryptionMechanism = Mechanism.get(decryptingMechanism);
        InitializationVectorParameters decryptInitializationVectorParameters = new InitializationVectorParameters(
                decryptionInitializationVector);
        decryptionMechanism.setParameters(decryptInitializationVectorParameters);
        session.decryptInit(decryptionMechanism, decryptionKey);
        byte[] decryptedData = session.decrypt(dataToBeDecrypted);
        return decryptedData;
    }


    public byte[] encryptRSA(Session session, byte[] dataToBeEncrypted,
                             RSAPublicKey encryptionKey, long encryptingMechanism) throws TokenException {
        byte[] encryptedData = null;
        Mechanism encryptionMechanism = Mechanism.get(encryptingMechanism);
        if (encryptionMechanism.isSingleOperationEncryptDecryptMechanism()) {
            session.encryptInit(encryptionMechanism, encryptionKey);
            encryptedData = session.encrypt(dataToBeEncrypted);
        }
        return encryptedData;
    }

    public byte[] decryptRSA(Session session, byte[] dataToBeDecrypted,
                             RSAPrivateKey decryptionKey, long decryptingMechanism) throws TokenException {
        byte[] decryptedData = null;
        Mechanism decryptionMechanism = Mechanism.get(decryptingMechanism);
        if (decryptionMechanism.isSingleOperationEncryptDecryptMechanism()) {
            session.decryptInit(decryptionMechanism, decryptionKey);
            decryptedData = session.decrypt(dataToBeDecrypted);
        }
        return decryptedData;
    }
}
