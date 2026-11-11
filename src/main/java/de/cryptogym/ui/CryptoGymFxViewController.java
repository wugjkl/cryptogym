package de.cryptogym.ui;

import javafx.fxml.FXML;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import de.cryptogym.controller.CryptoGymController;
import de.cryptogym.domain.BlockCipherMode;
import de.cryptogym.domain.CipherAlgorithm;
import de.cryptogym.domain.PaddingScheme;
import de.cryptogym.model.CryptoGymModel;

/**
 * JavaFX FXML View-Controller binding the graphical user interface controls defined in
 * {@code crypto-gym.fxml} to the {@link CryptoGymController} and {@link CryptoGymModel}.
 *
 * @author Daniel
 */
public class CryptoGymFxViewController
{
    @FXML
    private ComboBox<CipherAlgorithm> algorithmComboBox;

    @FXML
    private ComboBox<BlockCipherMode> modeComboBox;

    @FXML
    private ComboBox<PaddingScheme> paddingComboBox;

    @FXML
    private TextArea plaintextArea;

    @FXML
    private TextArea plaintextHexArea;

    @FXML
    private Label plaintextBytesLabel;

    @FXML
    private TextArea ciphertextHexArea;

    @FXML
    private Label ciphertextBytesLabel;

    @FXML
    private TextField keyHexField;

    @FXML
    private Label keyBytesLabel;

    @FXML
    private TextField ivHexField;

    @FXML
    private Label ivBytesLabel;

    @FXML
    private TextField statusField;

    private final CryptoGymController domainController = new CryptoGymController();

    /**
     * Initializes the JavaFX controls after FXML loading and populates the selector boxes.
     */
    @FXML
    public void initialize()
    {
        this.algorithmComboBox.getItems().setAll(CipherAlgorithm.values());
        this.modeComboBox.getItems().setAll(BlockCipherMode.values());
        this.paddingComboBox.getItems().setAll(PaddingScheme.values());

        CryptoGymModel model = this.domainController.getModel();
        this.algorithmComboBox.setValue(model.getAlgorithm());
        this.modeComboBox.setValue(model.getMode());
        this.paddingComboBox.setValue(model.getPadding());
        refreshViewFromModel();
    }

    /**
     * Handles the Encrypt button action from JavaFX UI.
     */
    @FXML
    public void handleEncrypt()
    {
        syncModelFromView();
        this.domainController.onEncrypt();
        refreshViewFromModel();
    }

    /**
     * Handles the Decrypt button action from JavaFX UI.
     */
    @FXML
    public void handleDecrypt()
    {
        syncModelFromView();
        this.domainController.onDecrypt();
        refreshViewFromModel();
    }

    /**
     * Handles the Generate Key button action from JavaFX UI.
     */
    @FXML
    public void handleGenerateKey()
    {
        syncModelFromView();
        CipherAlgorithm alg = this.domainController.getModel().getAlgorithm();
        int defaultBits = (alg == CipherAlgorithm.DES) ? 64 : 128;
        this.domainController.onGenerateKey(defaultBits);
        refreshViewFromModel();
    }

    /**
     * Handles the Generate IV button action from JavaFX UI.
     */
    @FXML
    public void handleGenerateIv()
    {
        syncModelFromView();
        this.domainController.onGenerateIv();
        refreshViewFromModel();
    }

    /**
     * Handles the Reset button action from JavaFX UI.
     */
    @FXML
    public void handleReset()
    {
        this.domainController.onReset();
        refreshViewFromModel();
    }

    private void syncModelFromView()
    {
        CryptoGymModel model = this.domainController.getModel();
        try
        {
            if (this.algorithmComboBox.getValue() != null)
            {
                model.setAlgorithm(this.algorithmComboBox.getValue());
            }
            if (this.modeComboBox.getValue() != null)
            {
                model.setMode(this.modeComboBox.getValue());
            }
            if (this.paddingComboBox.getValue() != null)
            {
                model.setPadding(this.paddingComboBox.getValue());
            }

            String hexPlain = this.plaintextHexArea.getText();
            String textPlain = this.plaintextArea.getText();
            if (hexPlain != null && !hexPlain.trim().isEmpty())
            {
                model.setPlaintextHex(hexPlain);
            }
            else
            {
                model.setPlaintextFromString(textPlain);
            }

            model.setCiphertextHex(this.ciphertextHexArea.getText());
            model.setKeyHex(this.keyHexField.getText());
            model.setIvHex(this.ivHexField.getText());
        }
        catch (IllegalArgumentException e)
        {
            model.setStatus("Invalid hexadecimal input: " + e.getMessage());
        }
    }

    private void refreshViewFromModel()
    {
        CryptoGymModel model = this.domainController.getModel();
        this.plaintextArea.setText(model.getPlaintextString());
        this.plaintextHexArea.setText(model.getPlaintextHex());
        this.plaintextBytesLabel.setText(model.getPlaintextLengthInBytes() + " Bytes");

        this.ciphertextHexArea.setText(model.getCiphertextHex());
        this.ciphertextBytesLabel.setText(model.getCiphertextLengthInBytes() + " Bytes");

        this.keyHexField.setText(model.getKeyHex());
        this.keyBytesLabel.setText(model.getKeyLengthInBytes() + " Bytes");

        this.ivHexField.setText(model.getIvHex());
        this.ivBytesLabel.setText(model.getIvLengthInBytes() + " Bytes");

        this.statusField.setText(model.getStatus());
    }
}
