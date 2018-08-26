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
import org.wso2.hsm.cryptoprovider.util.SessionInitiator;
import sun.security.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.util.Scanner;

public class Application {

    private char[] userPIN;
    private int slotNo;
    private Module pkcs11Module;
    private FileHandler fileHandler;
    private SessionInitiator sessionInitiator;
    private KeyRetriever keyRetriever;
    private Cipher cipher;

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
    }

    /**
     * This method starts the application and prompt for required for user inputs.
     */
    public void start() {
        String initialPromptText = "Available Cryptographic Operations \n" +
                "1. Key Generation \n" +
                "2. Encryption \n" +
                "3. Decryption \n" +
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
                default:
                    System.out.println("Invalid input!");
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
                        PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, privateKeyTemplate, publicKeyTemplate);
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
            System.out.println("Invalid input!");
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
        if (input.equals("1")) {
            AESSecretKey secretKeyTemplate = new AESSecretKey();
            secretKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            AESSecretKey secretKey = (AESSecretKey) keyRetriever.retrieveKey(session, secretKeyTemplate);
            byte[] initializationVector = new byte[16];
            byte[] encryptedData = cipher.encryptAES(session, dataToEncrypt, secretKey, initializationVector, PKCS11Constants.CKM_AES_CBC_PAD);
            fileHandler.saveFile("encrypted/sample", encryptedData);
            System.out.println("Encrypted text : " + new String(encryptedData));
        } else if (input.equals("2")) {
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            publicKeyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
            RSAPublicKey publicKey = (RSAPublicKey) keyRetriever.retrieveKey(session, publicKeyTemplate);
            byte[] encryptedData = cipher.encryptRSA(session, dataToEncrypt, publicKey, PKCS11Constants.CKM_RSA_PKCS);
            fileHandler.saveFile("encrypted/sample", encryptedData);
            System.out.println("Encrypted text : " + new String(encryptedData));
        } else {
            System.out.println("Invalid input");
        }
    }

    private void decrypt() throws TokenException, IOException {
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
            byte[] decryptedData = cipher.decryptAES(session, dataToDecrypt, secretKey, PKCS11Constants.CKM_AES_CBC_PAD, initializationVector);
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
            System.out.println("Invalid input!");
        }
        session.closeSession();
    }

    private String getInput(String promptText) {
        Scanner scanner = new Scanner(System.in);
        System.out.print(promptText);
        return scanner.nextLine();
    }
}
