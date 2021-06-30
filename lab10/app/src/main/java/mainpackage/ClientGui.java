package mainpackage;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class ClientGui {

    private final JTextArea send;
    private final Client client;

    public ClientGui() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        client = new Client();
        JFrame frame = new JFrame("client");
        JPanel mainPanel = new JPanel(new GridLayout(5, 1));
        frame.add(mainPanel);
        mainPanel.add(new JLabel("wpisz wiadomosc"));
        send = new JTextArea();
        mainPanel.add(send);
        JButton sendButton = new JButton("send");
        sendButton.addActionListener(e -> {
            try {
                sendMessage();
            } catch (IOException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException |
                    IllegalBlockSizeException | NoSuchPaddingException ioException) {
                ioException.printStackTrace();
            }
        });
        mainPanel.add(sendButton);
        mainPanel.add(new JLabel("otrzymane wiadomosci"));
        JTextArea get = new JTextArea();
        get.setEditable(false);
        get.setLineWrap(true);
        JScrollPane scrollPane = new JScrollPane(get);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(300,300);
        frame.setVisible(true);
        client.startConnection("127.0.0.1", 6000, get);
    }

    public void sendMessage() throws IOException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, NoSuchPaddingException {
        client.sendMessage(send.getText());
    }
}
