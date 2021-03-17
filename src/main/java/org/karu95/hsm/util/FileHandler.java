package org.karu95.hsm.util;

import java.io.*;
import java.util.Arrays;

public class FileHandler {


    /**
     * Constructor for FileHandler instance
     */
    public FileHandler() {
    }

    /**
     * Read a file.
     *
     * @param file : File to be read.
     * @return byte array of data contained in the file.
     */

    public byte[] readFile(File file) {
        InputStream inputStream = null;
        byte[] rawData = null;
        try {
            inputStream = new FileInputStream(file);
            byte[] dataBuffer = new byte[1024];
            int bytesRead;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            while ((bytesRead = inputStream.read(dataBuffer)) >= 0) {
                outputStream.write(dataBuffer, 0, bytesRead);
            }
            Arrays.fill(dataBuffer, (byte) 0);
            outputStream.flush();
            outputStream.close();
            rawData = outputStream.toByteArray();
        } catch (FileNotFoundException e) {
            System.out.println("File read error : Couldn't locate the file.\n" + e.getMessage());
        } catch (IOException e) {
            System.out.println("File read error : Couldn't read the file.\n" + e.getMessage());
        }
        return rawData;
    }

    /**
     * Save a file.
     *
     * @param file : File to be saved.
     * @param data : Data to be written to the file.
     */
    public void saveFile(File file, byte[] data) {
        try {
            if (!file.exists()) {
                file.getParentFile().mkdirs();
                file.createNewFile();
            }
            FileOutputStream outputStream = new FileOutputStream(file);
            outputStream.write(data);
            outputStream.flush();
            outputStream.close();
        } catch (IOException e) {
            System.out.println("File saving error : " + e.getMessage());
        }
    }
}
