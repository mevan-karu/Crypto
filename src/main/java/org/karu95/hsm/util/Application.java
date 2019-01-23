package org.karu95.hsm.util;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import org.apache.axiom.om.util.Base64;
import org.karu95.hsm.cryptoprovider.keyhandlers.KeyGenerator;
import org.karu95.hsm.cryptoprovider.keyhandlers.KeyRetriever;
import org.karu95.hsm.cryptoprovider.operators.Cipher;
import org.karu95.hsm.cryptoprovider.operators.HashGenerator;
import org.karu95.hsm.cryptoprovider.operators.SignatureHandler;
import org.karu95.hsm.cryptoprovider.util.MechanismResolver;
import org.karu95.hsm.cryptoprovider.util.SessionInitiator;
import sun.security.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.util.HashMap;
import java.util.Scanner;

public class Application {

    private char[] userPIN;
    private int slotNo;
    private Module pkcs11Module;
    private FileHandler fileHandler;
    private SessionInitiator sessionInitiator;
    private KeyRetriever keyRetriever;
    private Cipher cipher;
    private SignatureHandler signatureHandler;
    private HashGenerator hashGenerator;
    private HashMap<Integer, String> encryptionDecryptionMechanisms;
    private HashMap<Integer, String> signVerifyMechanisms;
    private MechanismResolver mechanismResolver;
    private boolean quit;

    /**
     * Constructor of the Application Class
     *
     * @param module  : Path to PKCS #11 Module
     * @param userPIN : User PIN of the selected slot
     * @param slotNo  : Selected slot
     */
    public Application(String module, String userPIN, int slotNo) {

        quit = false;
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
        signatureHandler = new SignatureHandler();
        hashGenerator = new HashGenerator();
        encryptionDecryptionMechanisms = new HashMap<Integer, String>();
        signVerifyMechanisms = new HashMap<Integer, String>();
        mechanismResolver = new MechanismResolver();
        updateAvailableMechanisms();
    }

    private void updateAvailableMechanisms() {

        int j = 1;
        int k = 1;
        for (String mechanismName : MechanismResolver.getMechanisms().keySet()) {
            Mechanism mechanism = Mechanism.get(MechanismResolver.getMechanisms().get(mechanismName));
            if (mechanism.isFullEncryptDecryptMechanism() || mechanism.isSingleOperationEncryptDecryptMechanism()) {
                encryptionDecryptionMechanisms.put(j, mechanismName);
                j += 1;
            } else if (mechanism.isFullSignVerifyMechanism()) {
                signVerifyMechanisms.put(k, mechanismName);
                k += 1;
            } else if (mechanism.isDigestMechanism()) {

            }
        }
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
                "7. Quit \n" +
                "Enter No. of required operation : ";
        while (!quit) {
            provideOperation(getInput(initialPromptText));
            System.out.println("\n");
        }
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
                case 7:
                    quit = true;
                    break;
                default:
                    System.out.println("Cryptographic operation selection : Invalid input!");
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void generateKey() throws TokenException {

        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
        try {
            String generateKeyPromptText = "Select key type \n" +
                    "1. RSA \n" +
                    "2. AES \n" +
                    "Enter no. of key type : ";
            String input = getInput(generateKeyPromptText);
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
        } finally {
            session.closeSession();
        }
    }

    private void encrypt() throws TokenException {

        String encryptPrompt = generatePromptText(encryptionDecryptionMechanisms);
        int input = Integer.valueOf(getInput(encryptPrompt));
        String pathPrompt = "Path of file to be encrypted = ";
        String path = getInput(pathPrompt);
        String keyLabelPrompt = "Label of the encryption key = ";
        String keyLabel = getInput(keyLabelPrompt);
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
        try {
            byte[] dataToEncrypt = fileHandler.readFile(path);
            if (encryptionDecryptionMechanisms.containsKey(input)) {
                Key keyTemplate = new Key();
                keyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
                Key key = (Key) keyRetriever.retrieveKey(session, keyTemplate);
                Mechanism encryptionMechanism = mechanismResolver.resolveMechanism("encrypt",
                        encryptionDecryptionMechanisms.get(input), dataToEncrypt);
                byte[] encryptedData = cipher.encrypt(session, dataToEncrypt, key, encryptionMechanism);
                if (encryptionMechanism.getParameters() instanceof InitializationVectorParameters) {
                    byte[] iv = ((InitializationVectorParameters)
                            encryptionMechanism.getParameters()).getInitializationVector();
                    byte[] encryptedDataWithIV = new byte[encryptedData.length +
                            iv.length];
                    System.arraycopy(iv, 0, encryptedDataWithIV, 0, iv.length);
                    System.arraycopy(encryptedData, 0, encryptedDataWithIV, iv.length, encryptedData.length);
                    encryptedData = encryptedDataWithIV;
                }
                fileHandler.saveFile("encrypted/sample", Base64.encode(encryptedData).getBytes());
                System.out.println("Encrypted text : " + new String(encryptedData));
            } else {
                System.out.println("Encryption mechanism selection : Invalid input!");
            }
        } finally {
            session.closeSession();
        }
    }

    private void decrypt() throws TokenException {

        String decryptPrompt = generatePromptText(encryptionDecryptionMechanisms);
        int input = Integer.valueOf(getInput(decryptPrompt));
        String pathPrompt = "Path of file to be decrypted : ";
        String path = getInput(pathPrompt);
        String keyLabelPrompt = "Label of the decryption key : ";
        String keyLabel = getInput(keyLabelPrompt);
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
        try {
            byte[] dataToDecrypt = Base64.decode(new String(fileHandler.readFile(path)));
            if (encryptionDecryptionMechanisms.containsKey(input)) {
                Key keyTemplate = new Key();
                keyTemplate.getLabel().setCharArrayValue(keyLabel.toCharArray());
                Key decryptionKey = (Key) keyRetriever.retrieveKey(session, keyTemplate);
                Mechanism decryptMechanism = mechanismResolver.resolveMechanism("decrypt",
                        encryptionDecryptionMechanisms.get(input), dataToDecrypt);
                if (decryptMechanism.getParameters() instanceof InitializationVectorParameters) {
                    byte[] iv = ((InitializationVectorParameters)
                            decryptMechanism.getParameters()).getInitializationVector();
                    byte[] dataToDecryptWithoutIV = new byte[dataToDecrypt.length - iv.length];
                    System.arraycopy(dataToDecrypt, iv.length, dataToDecryptWithoutIV, 0, dataToDecrypt.length - iv.length);
                    dataToDecrypt = dataToDecryptWithoutIV;
                }
                byte[] decryptedData = cipher.decrypt(session, dataToDecrypt, decryptionKey,
                        decryptMechanism);
                fileHandler.saveFile("decrypted/sample.txt", decryptedData);
                System.out.println("Decrypted text : " + new String(decryptedData));
            } else {
                System.out.println("Decryption mechanism selection : Invalid input!");
            }
        } finally {
            session.closeSession();
        }
    }

    private void sign() throws TokenException {

        String promptSignMechanism = generatePromptText(signVerifyMechanisms);
        int input = Integer.valueOf(getInput(promptSignMechanism));
        if (signVerifyMechanisms.containsKey(input)) {
            String filePathPrompt = "Path of file to be signed : ";
            String filePath = getInput(filePathPrompt);
            String privateKeyPrompt = "Label of the private key to sign : ";
            String label = getInput(privateKeyPrompt);
            RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
            privateKeyTemplate.getLabel().setCharArrayValue(label.toCharArray());
            Mechanism mechanism = mechanismResolver.resolveMechanism("sign",
                    signVerifyMechanisms.get(input), null);
            Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
            try {
                RSAPrivateKey privateKey = (RSAPrivateKey) keyRetriever.retrieveKey(session, privateKeyTemplate);
                byte[] signature = signatureHandler.sign(session,
                        fileHandler.readFile(filePath), mechanism, privateKey);
                System.out.println("Signature : " + new String(signature));
                fileHandler.saveFile("signature/sample", signature);
                System.out.println();
            } finally {
                session.closeSession();
            }
        } else {
            System.out.println("Sign mechanism selection : Invalid input!!");
        }
    }

    private void verify() throws TokenException {

        String promptVerifyMechanism = generatePromptText(signVerifyMechanisms);
        int input = Integer.valueOf(getInput(promptVerifyMechanism));
        if (signVerifyMechanisms.containsKey(input)) {
            String filePathPrompt = "Path of file to be verified : ";
            String filePath = getInput(filePathPrompt);
            String signaturePrompt = "Signature containing file path : ";
            String signaturePath = getInput(signaturePrompt);
            String publicKeyPrompt = "Label of the public key to verify : ";
            String label = getInput(publicKeyPrompt);
            RSAPublicKey publicKeyTemplate = new RSAPublicKey();
            publicKeyTemplate.getLabel().setCharArrayValue(label.toCharArray());
            Mechanism mechanism = mechanismResolver.resolveMechanism("verify",
                    signVerifyMechanisms.get(input), null);
            Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
            try {
                RSAPublicKey publicKey = (RSAPublicKey) keyRetriever.retrieveKey(session, publicKeyTemplate);
                boolean verification = signatureHandler.verify(session, fileHandler.readFile(filePath),
                        fileHandler.readFile(signaturePath), mechanism, publicKey);
                System.out.println("Verification : " + verification);
            } finally {
                session.closeSession();
            }
        } else {
            System.out.println("Verify mechanism selection : Invalid input!!");
        }
    }

    private String generatePromptText(HashMap<Integer, String> mechanisms) {

        String promptText = "Select the number of the required mechanism\n";
        for (int i = 1; i <= mechanisms.size(); i++) {
            promptText += String.valueOf(i) + ". " + mechanisms.get(i) + "\n";
        }
        promptText += "Enter the number : ";
        return promptText;
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
        Session session = sessionInitiator.initiateSession(pkcs11Module, userPIN, slotNo);
        String hash = hashGenerator.hash(session, fileHandler.readFile(filePath), mechanism);
        System.out.println("Hash value : " + hash);
    }

    private String getInput(String promptText) {

        Scanner scanner = new Scanner(System.in);
        System.out.print(promptText);
        return scanner.nextLine();
    }
}
