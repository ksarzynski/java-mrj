package mainpackage;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Runnable runnable = () -> {
            try {
                new ServerGui();
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        };

        Thread thread = new Thread(runnable);
        thread.start();
        new ClientGui();
    }
}
