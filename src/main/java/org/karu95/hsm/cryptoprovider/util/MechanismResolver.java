package org.karu95.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.RSAPkcsOaepParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.util.HashMap;
import java.util.Random;

public class MechanismResolver {

    private static HashMap<String, Long> mechanisms = new HashMap<String, Long>() {{
        /**
         * Encrypt/Decrypt mechanisms
         */
        //DES mechanisms
        put("DES/CBC/NoPadding", PKCS11Constants.CKM_DES_CBC);
        put("DES/CBC/PKCS5Padding", PKCS11Constants.CKM_DES_CBC_PAD);
        put("DES/ECB/NoPadding", PKCS11Constants.CKM_DES_ECB);

        //DES3 mechanisms
        put("DESede/CBC/NoPadding", PKCS11Constants.CKM_DES3_CBC);
        put("DESede/CBC/PKCS5Padding", PKCS11Constants.CKM_DES3_CBC_PAD);
        put("DESede/ECB/NoPadding", PKCS11Constants.CKM_DES3_ECB);

        //AES mechanisms
        put("AES/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_128/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_192/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES_256/CBC/NoPadding", PKCS11Constants.CKM_AES_CBC);
        put("AES/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_128/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_192/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES_256/CBC/PKCS5Padding", PKCS11Constants.CKM_AES_CBC_PAD);
        put("AES/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_128/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_192/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES_256/ECB/NoPadding", PKCS11Constants.CKM_AES_ECB);
        put("AES/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_128/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_192/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES_256/CCM/NoPadding", PKCS11Constants.CKM_AES_CCM);
        put("AES/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_128/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_192/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);
        put("AES_256/GCM/NoPadding", PKCS11Constants.CKM_AES_GCM);

        //RC2


        //RSA mechanisms
        put("RSA/NONE/OAEPWithMD5AndMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/NONE/OAEPWithSHA1AndMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/NONE/OAEPWithSHA224AndMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/NONE/OAEPWithSHA256AndMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/NONE/OAEPWithSHA384AndMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/NONE/OAEPWithSHA512AndMGF1Padding", PKCS11Constants.CKM_RSA_PKCS_OAEP);
        put("RSA/NONE/PKCS1Padding", PKCS11Constants.CKM_RSA_PKCS);
        put("RSA/NONE/NoPadding", PKCS11Constants.CKM_RSA_X_509);
        put("RSA/NONE/ISO9796Padding", PKCS11Constants.CKM_RSA_9796);

        //Blowfish mechanisms
        put("Blowfish/CBC/NoPadding", PKCS11Constants.CKM_BLOWFISH_CBC);
        put("Blowfish/CBC/PKCS5Padding", PKCS11Constants.CKM_BLOWFISH_CBC);

        /**
         * Sign/Verify mechanisms
         */
        put("RawDSA", PKCS11Constants.CKM_DSA);
        put("DSA", PKCS11Constants.CKM_DSA_SHA1);

        //ECDSA sign/verify mechanisms
        put("NONEwithECDSA", PKCS11Constants.CKM_ECDSA);
        put("SHA1withECDSA", PKCS11Constants.CKM_ECDSA_SHA1);

        //RSA sign/verify mechanisms
        put("MD2withRSA", PKCS11Constants.CKM_MD2_RSA_PKCS);
        put("MD5withRSA", PKCS11Constants.CKM_MD5_RSA_PKCS);
        put("SHA1withRSA", PKCS11Constants.CKM_SHA1_RSA_PKCS);
        put("SHA256withRSA", PKCS11Constants.CKM_SHA256_RSA_PKCS);
        put("SHA384withRSA", PKCS11Constants.CKM_SHA384_RSA_PKCS);
        put("SHA512withRSA", PKCS11Constants.CKM_SHA512_RSA_PKCS);
        put("RipeMd128withRSA", PKCS11Constants.CKM_RIPEMD128_RSA_PKCS);
        put("RipeMd160withRSA", PKCS11Constants.CKM_RIPEMD160_RSA_PKCS);

        //DSA sign/verify mechanisms
        put("SHA1withDSA", PKCS11Constants.CKM_DSA_SHA1);

        /**
         * Digest mechanisms
         */
        put("SHA1", PKCS11Constants.CKM_SHA_1);
        put("SHA256", PKCS11Constants.CKM_SHA256);
        put("SHA384", PKCS11Constants.CKM_SHA384);
        put("SHA512", PKCS11Constants.CKM_SHA512);
        put("MD2", PKCS11Constants.CKM_MD2);
        put("MD5", PKCS11Constants.CKM_MD5);
        put("RipeMd128", PKCS11Constants.CKM_RIPEMD128);
        put("RipeMd160", PKCS11Constants.CKM_RIPEMD160);
    }};

    private static HashMap<Long, String> parameterRequiredMechanisms = new HashMap<Long, String>() {{
        put(PKCS11Constants.CKM_AES_CBC, "IV16");
        put(PKCS11Constants.CKM_AES_CBC_PAD, "IV16");

        put(PKCS11Constants.CKM_RSA_PKCS_OAEP, "OAEP");

        put(PKCS11Constants.CKM_DES3_CBC, "IV8");
        put(PKCS11Constants.CKM_DES3_CBC_PAD, "IV8");

        put(PKCS11Constants.CKM_DES_CBC, "IV8");
        put(PKCS11Constants.CKM_DES_CBC_PAD, "IV8");
    }};

    /**
     * Method to retrieve of mechanisms.
     *
     * @return HashMap of mechanisms.
     */
    public static HashMap<String, Long> getMechanisms() {
        return mechanisms;
    }

    public MechanismResolver() {
    }

    /**
     * Method to resolve the mechanism when mechanism specification is given.
     *
     * @param operation              : Operation related to the mechanism.
     * @param mechanismSpecification : Standard JCE specified name of the mechanism.
     * @param data                   : Data used for cryptographic operation.
     * @return : Properly configured mechanism.
     */
    public Mechanism resolveMechanism(String operation, String mechanismSpecification, byte[] data) {
        Mechanism mechanism = null;
        if (mechanisms.containsKey(mechanismSpecification)) {
            mechanism = Mechanism.get(mechanisms.get(mechanismSpecification));
            if (parameterRequiredMechanisms.containsKey(mechanism.getMechanismCode())) {
                String parameterSpec = parameterRequiredMechanisms.get(mechanism.getMechanismCode());
                if (parameterSpec.contains("IV")) {
                    int ivSize = Integer.valueOf((String)
                            parameterSpec.subSequence(2, parameterSpec.length()));
                    mechanism.setParameters(getInitializationVectorParameters(operation, data, ivSize));
                } else if (parameterSpec.contains("OAEP")) {
                    String[] specification = mechanismSpecification.split("/");
                    mechanism.setParameters(getOAEPParameters(specification[specification.length - 1]));
                }
            }
        }
        return mechanism;
    }

    private RSAPkcsOaepParameters getOAEPParameters(String parameter) {
        String[] specParams = parameter.split("With");
        String[] oaepParams = specParams[1].split("And");
        if (mechanisms.containsKey(oaepParams[0])) {
            return new RSAPkcsOaepParameters(Mechanism.get(mechanisms.get(oaepParams[0])), 1L,
                    PKCS11Constants.CKZ_DATA_SPECIFIED, null);
        }
        return null;
    }

    private InitializationVectorParameters getInitializationVectorParameters(String operation,
                                                                             byte[] data, int ivSize) {
        byte[] iv = new byte[ivSize];
        if (operation.equals("encrypt")) {
            new Random().nextBytes(iv);
        } else if (operation.equals("decrypt")) {
            System.arraycopy(data, 0, iv, 0, ivSize);
        }
        return new InitializationVectorParameters(iv);
    }

    /*
    private static RSAPkcsPssParameters getRSAPSSParameters() {

    }
    */
}
