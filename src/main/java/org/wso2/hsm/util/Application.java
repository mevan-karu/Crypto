package org.wso2.hsm.util;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import org.wso2.hsm.cryptoprovider.keyhandlers.KeyGenerator;
import org.wso2.hsm.cryptoprovider.keyhandlers.KeyRetriever;
import org.wso2.hsm.cryptoprovider.operators.Cipher;
import org.wso2.hsm.cryptoprovider.operators.HashGenerator;
import org.wso2.hsm.cryptoprovider.operators.SignatureHandler;
import org.wso2.hsm.cryptoprovider.util.SessionInitiator;
import sun.security.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

public class Application {

    private char[] userPIN;
    private int slotNo;
    private Module pkcs11Module;
    private FileHandler fileHandler;
    private SessionInitiator sessionInitiator;
    private KeyRetriever keyRetriever;
    private Cipher cipher;
    private SignatureHandler signaturehandler;
    private HashGenerator hashGenerator;

    /**
     * Constructor of the Application Class
     *
     * @param module  : Path to PKCS #11 Module
     * @param userPIN : User PIN of the selected slot
     * @param slotNo  : Selected slot
     */
    public Application(String module, String userPIN, int slotNo) {
        this.userPIN = userPIN.toCharArray();
        this.slotNo = slotNo;
        try {
            pkcs11Module = Module.getInstance(module);
            pkcs11Module.initialize(null);
        } catch (IOException e) {
            System.out.println("Couldn't find PKCS #11 module.");
        } catch (TokenException e) {
            System.out.println("Initialize the token.");
        }
        fileHandler = new FileHandler();
        sessionInitiator = SessionInitiator.defaultSessionInitiator();
        keyRetriever = new KeyRetriever();
        cipher = new Cipher();
        signaturehandler = new SignatureHandler();
        hashGenerator = new HashGenerator();
    }

    /**
     * This method starts the application and prompt for required for user inputs.
     */
    public void start() {
        String initialPromptText = "Available Cryptographic Operations \n" +
                "1. Key Generation \n" +
                "2. Encryption \n" +
                "3. Decryption \n" +
                "4. Sign \n" +
                "5. Verify \n" +
                "6. Hash \n" +
                "Enter No. of required operation : ";

        provideOperation(getInput(initialPromptText));
    }


    private void provideOperation(String userInput) {
        try {
            switch (Integer.valueOf(userInput)) {
                case 1:
                    generateKey();
                    break;
                case 2:
                    encrypt();
                    break;
                case 3:
                    decrypt();
                    break;
                case 4:
                    sign();
                    break;
                case 5:
                    verify();
                    break;
                case 6:
                    hash();
                default:
                    System.out.println("Cryptographic operation selection : Invalid input!");
                    break;
            }
        } catch (Exception e) {
            System.out.println("Input should be a number!!!\n" + e.getMessage());
        }
    }


    private void generateKey() throws TokenException {
        String generateKeyPromptText = "Select key type \n" +
                "1. RSA \n" +
                "2. AES \n" +
                "Enter no. of key type : ";
        String input = getInput(generateKeyPromptText);
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
        if (input.equals("1")) {
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
            String promptKeyGenerationMechanism = "Select key generation mechanism \n" +
                    "1. PKCS Key Pair\n" +
                    "2. X9.31 Key Pair\n" +
                    "Enter no. of generation type : ";
            String keyGeneration = getInput(promptKeyGenerationMechanism);
            long keyGenerationMechanism = 0;
            if (keyGeneration.equals("1")) {
                keyGenerationMechanism = PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
            } else if (keyGeneration.equals("2")) {
                keyGenerationMechanism = PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN;
            } else {
                System.out.println("RSA key generation mechanism selection : Invalid input!");
                return;
            }
            String templatePromptText = "Provide RSA key pair details as sample given. \n" +
                    "Sample input : label(Shouldn't contain spaces) length(1024-2048) \n" +
                    "Input : ";
            byte[] publicExponentBytes = {0x01, 0x00, 0x001};
            publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
            input = getInput(templatePromptText);
            String[] inputs = input.split(" ");
            if (inputs.length == 2) {
                privateKeyTemplate.getLabel().setCharArrayValue((inputs[0] + "PrivateKey").toCharArray());
                publicKeyTemplate.getLabel().setCharArrayValue((inputs[0] + "PublicKey").toCharArray());

                publicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(inputs[1]));
                boolean generated = KeyGenerator.getKeyGenerator().generateRSAKeyPair(session,
                        keyGenerationMechanism, privateKeyTemplate, publicKeyTemplate);
                if (generated) {
                    System.out.println("RSA key pair successfully generated!");
                } else {
                    System.out.println("RSA key pair generation failed!");
                }
            }
        } else if (input.equals("2")) {
            AESSecretKey secretKeyTemplate = new AESSecretKey();
            String templatePromptText = "Provide AES key details as sample given. \n" +
                    "Sample input : label(Shouldn't contain spaces) length(16-32) \n" +
                    "Input : ";
            secretKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
            secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
            secretKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);
            input = getInput(templatePromptText);
            String[] inputs = input.split(" ");
            if (inputs.length == 2) {
                secretKeyTemplate.getLabel().setCharArrayValue(inputs[0].toCharArray());
                secretKeyTemplate.getValueLen().setLongValue(new Long(inputs[1]));
                boolean generated = KeyGenerator.getKeyGenerator().generateAESKey(session, secretKeyTemplate);
                if (generated) {
                    System.out.println("AES key successfully generated!");
                } else {
                    System.out.println("AES key generation failed!");
                }
            }
        } else {
            System.out.println("Key generation mechanism selection : Invalid input!");
        }
    }

    private void encrypt() throws IOException, TokenException {
        String encryptPrompt = "Select encryption mechanism \n" +
                "1. AES encryption \n" +
                "2. RSA encryption \n" +
                "Enter no. of encryption type : ";
        String input = getInput(encryptPrompt);
        String pathPrompt = "Path of file to be encrypted = ";
        String path = getInput(pathPrompt);
        String keyLabelPrompt = "Label of the encryption key = ";
        String keyLabel = getInput(keyLabelPrompt);
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, 0);
        byte[] dataToEncrypt = fileHandler.readFile(path);
        long encryptionMechanism = 0;
        if (input.equals("1")) {
            AESSecretKey secretKeyTemplate = new AESSecretKey();
            secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            AESSecretKey secretKey = (AESSecretKey) keyRetriever.retrieveKey(session, secretKeyTemplate);
            byte[] initializationVector = new byte[16];
            byte[] encryptedData = cipher.encryptAES(session, dataToEncrypt, secretKey,
                    initializationVector, PKCS11Constants.CKM_AES_CBC_PAD);
            fileHandler.saveFile("encrypted/sample", encryptedData);
            System.out.println("Encrypted text : " + new String(encryptedData));
        } else if (input.equals("2")) {
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            publicKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            RSAPublicKey publicKey = (RSAPublicKey) keyRetriever.retrieveKey(session, publicKeyTemplate);
            byte[] encryptedData = cipher.encryptRSA(session, dataToEncrypt, publicKey, encryptionMechanism);
            fileHandler.saveFile("encrypted/sample", encryptedData);
            System.out.println("Encrypted text : " + new String(encryptedData));
        } else {
            System.out.println("Encryption mechanism selection : Invalid input!");
        }
    }

    private void decrypt() throws TokenException {
        String decryptPrompt = "Select decryption mechanism \n" +
                "1. AES decryption \n" +
                "2. RSA decryption \n" +
                "Enter no. of the decryption type : ";
        String input = getInput(decryptPrompt);
        String pathPrompt = "Path of file to be decrypted : ";
        String path = getInput(pathPrompt);
        String keyLabelPrompt = "Label of the decryption key : ";
        String keyLabel = getInput(keyLabelPrompt);
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, 0);
        byte[] dataToDecrypt = fileHandler.readFile(path);
        if (input.equals("1")) {
            AESSecretKey secretKeyTemplate = new AESSecretKey();
            secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            AESSecretKey secretKey = (AESSecretKey) keyRetriever.retrieveKey(session, secretKeyTemplate);
            byte[] initializationVector = new byte[16];
            byte[] decryptedData = cipher.decryptAES(session, dataToDecrypt, secretKey,
                    PKCS11Constants.CKM_AES_CBC_PAD, initializationVector);
            fileHandler.saveFile("decrypted/sample.txt", decryptedData);
            System.out.println("Decrypted text : " + new String(decryptedData));
        } else if (input.equals("2")) {
            RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
            privateKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            RSAPrivateKey privateKey = (RSAPrivateKey) keyRetriever.retrieveKey(session, privateKeyTemplate);
            byte[] decryptedData = cipher.decryptRSA(session, dataToDecrypt, privateKey, PKCS11Constants.CKM_RSA_PKCS);
            fileHandler.saveFile("decrypted/sample.txt", decryptedData);
            System.out.println("Decrypted text : " + new String(decryptedData));
        } else {
            System.out.println("Decryption mechanism selection : Invalid input!");
        }
        session.closeSession();
    }

    private void sign() throws TokenException {
        String promptSignMechanism = "Select sign mechanism \n" +
                "1. RSA \n" +
                "Select mechanism : ";
        String input = getInput(promptSignMechanism);
        if (input.equals("1")) {
            String filePathPrompt = "Path of file to be signed : ";
            String filePath = getInput(filePathPrompt);
            String privateKeyPrompt = "Label of the private key to sign : ";
            String label = getInput(privateKeyPrompt);
            Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, 0);
            long mechanism = selectSignMechanism();
            RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
            privateKeyTemplate.getLabel().setCharArrayValue(label.toCharArray());
            RSAPrivateKey privateKey = (RSAPrivateKey) keyRetriever.retrieveKey(session, privateKeyTemplate);
            byte[] signature = signaturehandler.fullSign(session,
                    fileHandler.readFile(filePath), mechanism, privateKey);
            System.out.println("Signature : " + Arrays.toString(signature));
            fileHandler.saveFile("signature/sample", signature);
            System.out.println();
            session.closeSession();
        } else {
            System.out.println("Sign mechanism selection : Invalid input!!");
        }
    }

    private void verify() throws TokenException {
        String promptVerifyMechanism = "Select verify mechanism \n" +
                "1. RSA \n" +
                "Select mechanism : ";
        String input = getInput(promptVerifyMechanism);
        if (input.equals("1")) {
            String filePathPrompt = "Path of file to be verified : ";
            String filePath = getInput(filePathPrompt);
            String signaturePrompt = "Signature containing file path : ";
            String signaturePath = getInput(signaturePrompt);
            String publicKeyPrompt = "Label of the public key to verify : ";
            String label = getInput(publicKeyPrompt);
            Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, 0);
            long mechanism = selectSignMechanism();
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            publicKeyTemplate.getLabel().setCharArrayValue(label.toCharArray());
            RSAPublicKey publicKey = (RSAPublicKey) keyRetriever.retrieveKey(session, publicKeyTemplate);
            boolean verification = signaturehandler.fullVerify(session, fileHandler.readFile(filePath),
                    fileHandler.readFile(signaturePath), mechanism, publicKey);
            System.out.println("Verification : " + verification);
            session.closeSession();
        } else {
            System.out.println("Verify mechanism selection : Invalid input!!");
        }
    }

    private long selectSignMechanism() {
        String mechanismPrompt = "Select full sign/verify mechanism\n" +
                "1. SHA-1\n" +
                "2. SHA-256\n" +
                "3. SHA-384\n" +
                "4. SHA-512\n" +
                "5. MD-5\n" +
                "Selected full sign/verify mechanism : ";
        String selectedInput = getInput(mechanismPrompt);
        long mechanism = 0;
        switch (Integer.valueOf(selectedInput)) {
            case 1:
                mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                break;
            case 2:
                mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
                break;
            case 3:
                mechanism = PKCS11Constants.CKM_SHA384_RSA_PKCS;
                break;
            case 4:
                mechanism = PKCS11Constants.CKM_SHA512_RSA_PKCS;
                break;
            case 5:
                mechanism = PKCS11Constants.CKM_MD5_RSA_PKCS;
                break;
            default:
                System.out.println("Full sign/verify mechanism selection : Invalid input!");
                break;
        }
        return mechanism;
    }

    private void hash() {
        String hashPrompt = "Select hashing mechanism \n" +
                "1. SHA-1\n" +
                "2. SHA-256\n" +
                "3. SHA-384\n" +
                "4. SHA-512\n" +
                "5. MD-5\n" +
                "Selected hashing mechanism : ";
        String selectedInput = getInput(hashPrompt);
        long mechanism = 0;
        switch (Integer.valueOf(selectedInput)) {
            case 1:
                mechanism = PKCS11Constants.CKM_SHA_1;
                break;
            case 2:
                mechanism = PKCS11Constants.CKM_SHA256;
                break;
            case 3:
                mechanism = PKCS11Constants.CKM_SHA384;
                break;
            case 4:
                mechanism = PKCS11Constants.CKM_SHA512;
                break;
            case 5:
                mechanism = PKCS11Constants.CKM_MD5;
                break;
            default:
                System.out.println("Hashing mechanism selection : Invalid input!");
                break;
        }
        String filePrompt = "Path of file to be hashed : ";
        String filePath = getInput(filePrompt);
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, 0);
        String hash = hashGenerator.hash(session, fileHandler.readFile(filePath), mechanism);
        System.out.println("Hash value : " + hash);
    }

    private String getInput(String promptText) {
        Scanner scanner = new Scanner(System.in);
        System.out.print(promptText);
        return scanner.nextLine();
    }
}
