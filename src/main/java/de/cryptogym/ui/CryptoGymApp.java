package de.cryptogym.ui;

import java.io.IOException;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * JavaFX Application entry point for the Crypto Gym GUI as specified in {@code cg-req.pdf}.
 *
 * @author Daniel
 */
public class CryptoGymApp extends Application
{
    /**
     * Starts the primary JavaFX stage and loads {@code crypto-gym.fxml}.
     *
     * @param primaryStage primary application window
     * @throws IOException if the FXML layout resource cannot be loaded
     */
    @Override
    public void start(Stage primaryStage) throws IOException
    {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/de/cryptogym/ui/crypto-gym.fxml"));
        Parent root = loader.load();
        primaryStage.setTitle("Crypto Gym - Symmetric Block Ciphers");
        primaryStage.setScene(new Scene(root, 780, 620));
        primaryStage.show();
    }

    /**
     * Launches the JavaFX application.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args)
    {
        launch(args);
    }
}
