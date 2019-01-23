package org.karu95.hsm.util;

import iaik.pkcs.pkcs11.TokenException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Main {

    /**
     * main method of Crypto
     *
     * @param args : Initialization args
     */
    public static void main(String[] args) throws IOException, TokenException {
        Properties properties = new Properties();
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream stream = classLoader.getResourceAsStream("properties/pkcs11.properties");
        try {
            properties.load(stream);
        } catch (IOException e) {
            System.out.println("Unable to read/find the pkcs11.properties file.");
        }
        Application application = new Application(properties.getProperty("Module"),
                properties.getProperty("UserPIN"), Integer.valueOf(properties.getProperty("SlotNo")));
        application.start();
    }
}
    