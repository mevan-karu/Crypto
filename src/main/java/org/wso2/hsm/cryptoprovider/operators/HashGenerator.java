package org.wso2.hsm.cryptoprovider.operators;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;

import java.math.BigInteger;

public class HashGenerator {

    /**
     * Constructor for hash generation.
     */
    public HashGenerator() {
    }

    /**
     * Method to hash a provided set of data using given mechanism.
     *
     * @param session         : Session to generate the hash.
     * @param dataToBeHashed  : Data that needs to be hashed.
     * @param digestMechanism : Hashing mechanism.
     * @return hash value as a string.
     * @throws TokenException
     */
    public String hash(Session session, byte[] dataToBeHashed, long digestMechanism) {
        String hashValue = null;
        Mechanism hashingMechanism = Mechanism.get(digestMechanism);
        if (hashingMechanism.isDigestMechanism()) {
            try {
                session.digestInit(hashingMechanism);
                byte[] digestVal = session.digest(dataToBeHashed);
                hashValue = new BigInteger(1, digestVal).toString(16);
            } catch (TokenException e) {
                System.out.println("Hash generation error : " + e.getMessage());
            }
        }
        return hashValue;
    }
}
