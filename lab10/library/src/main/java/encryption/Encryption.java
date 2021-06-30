package encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Encryption {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private Socket clientSocket;
    private PublicKey receivedKey;

    public Encryption() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public Socket getClientSocket(){ return clientSocket; }

    public byte[] encrypt(String secretMessage, PublicKey publicKey) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
        return encryptCipher.doFinal(secretMessageBytes);
    }

    public String decrypt(PrivateKey privateKey, byte[] encryptedMessageBytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    public void sendMessage(String msg, OutputStream outputStream) throws
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        byte[] encodedMsg = encrypt(msg, receivedKey);
        System.out.println("Message to send: " + msg);
        System.out.println("Encoded message: " + Arrays.toString(encodedMsg));
        outputStream.write(encrypt(msg, receivedKey));
    }

    public void startServer(int port) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        ServerSocket serverSocket = new ServerSocket(port);
        clientSocket = serverSocket.accept();
        PrintWriter printWriter = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));;

        // ---------- get client's public key ---------- //
        String keyString = null;
        while (keyString == null) {

            try {
                keyString = bufferedReader.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        byte[] byteKey = Base64.getDecoder().decode(keyString.getBytes());
        EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        receivedKey = kf.generatePublic(X509publicKey);
        // --------------------------------------------- //


        // ---------- send public key to client ---------- //
        String key = Base64.getEncoder().withoutPadding().encodeToString(publicKey.getEncoded());
        printWriter.println(key);
        // ----------------------------------------------- //
    }

    public void startClient(String ip, int port) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        clientSocket = new Socket(ip, port);
        PrintWriter printWriter = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        // ---------- send public key to server ---------- //
        String key = Base64.getEncoder().withoutPadding().encodeToString(publicKey.getEncoded());
        printWriter.println(key);
        // ----------------------------------------------- //


        // ---------- get server's public key ---------- //
        String keyString = null;
        while (keyString == null) {

            try {
                keyString = bufferedReader.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        byte[] byteKey = Base64.getDecoder().decode(keyString.getBytes());
        EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        receivedKey = kf.generatePublic(X509publicKey);
        // --------------------------------------------- //
    }

    public void start(JTextArea textArea){

        // ---------- wait for incoming messages ---------- //
        Runnable runnable = () -> {
            String msg = "initialized";
            while (true) {
                try {
                    msg = decrypt(privateKey,
                            clientSocket.getInputStream().readNBytes(256));
                } catch (IOException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException |
                        BadPaddingException | NoSuchPaddingException e) {
                    e.printStackTrace();
                }
                if (".".equals(msg)) {
                    System.out.println("good bye");
                    break;
                }
                textArea.setText(textArea.getText() + msg + "\n");
            }
        };

        Thread thread = new Thread(runnable);
        thread.start();
        // ------------------------------------------------ //
    }
}
