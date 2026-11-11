package cryptogym;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Encapsulated Model (DTO) representing the state of all Crypto Gym fields for Sheet 1
 * (Exercises 1.4 and 1.5, based on Chapter 1, pages 1-16).
 * <p>
 * Protects internal byte arrays against external mutation by keeping all fields private
 * and performing defensive array copies on every setter and getter call.
 * </p>
 *
 * @author Daniel
 */
class CryptoGymState
{
    private String plaintext = "";
    private byte[] plaintextBytes = new byte[0];
    private byte[] ciphertextBytes = new byte[0];
    private byte[] keyBytes = new byte[0];
    private byte[] ivBytes = new byte[0];
    private String status = "Ready";

    /**
     * Returns the current plaintext string.
     *
     * @return non-null plaintext string
     */
    public String getPlaintext()
    {
        return this.plaintext;
    }

    /**
     * Updates the plaintext string and stores a defensive copy of its raw byte array.
     *
     * @param text     plaintext string; if {@code null}, defaults to empty string
     * @param rawBytes raw byte representation; if {@code null}, defaults to empty array
     */
    public void setPlaintext(String text, byte[] rawBytes)
    {
        this.plaintext = (text != null) ? text : "";
        this.plaintextBytes = copyArray(rawBytes);
    }

    /**
     * Returns a defensive copy of the raw plaintext bytes.
     *
     * @return non-null copy of plaintext bytes
     */
    public byte[] getPlaintextBytes()
    {
        return copyArray(this.plaintextBytes);
    }

    /**
     * Returns a defensive copy of the raw ciphertext bytes.
     *
     * @return non-null copy of ciphertext bytes
     */
    public byte[] getCiphertextBytes()
    {
        return copyArray(this.ciphertextBytes);
    }

    /**
     * Updates the raw ciphertext bytes using a defensive copy.
     *
     * @param bytes ciphertext byte array
     */
    public void setCiphertextBytes(byte[] bytes)
    {
        this.ciphertextBytes = copyArray(bytes);
    }

    /**
     * Returns a defensive copy of the secret key bytes.
     *
     * @return non-null copy of key bytes
     */
    public byte[] getKeyBytes()
    {
        return copyArray(this.keyBytes);
    }

    /**
     * Updates the secret key bytes using a defensive copy.
     *
     * @param bytes key byte array
     */
    public void setKeyBytes(byte[] bytes)
    {
        this.keyBytes = copyArray(bytes);
    }

    /**
     * Returns a defensive copy of the Initialization Vector (IV) bytes.
     *
     * @return non-null copy of IV bytes
     */
    public byte[] getIvBytes()
    {
        return copyArray(this.ivBytes);
    }

    /**
     * Updates the Initialization Vector (IV) bytes using a defensive copy.
     *
     * @param bytes IV byte array
     */
    public void setIvBytes(byte[] bytes)
    {
        this.ivBytes = copyArray(bytes);
    }

    /**
     * Returns the current status or error message.
     *
     * @return non-null status message
     */
    public String getStatus()
    {
        return this.status;
    }

    /**
     * Updates the status message.
     *
     * @param status new status string
     */
    public void setStatus(String status)
    {
        this.status = (status != null) ? status : "";
    }

    /**
     * Resets all fields and byte arrays to their initial empty state.
     */
    public void reset()
    {
        this.plaintext = "";
        this.plaintextBytes = new byte[0];
        this.ciphertextBytes = new byte[0];
        this.keyBytes = new byte[0];
        this.ivBytes = new byte[0];
        this.status = "Reset to initial state";
    }

    // Вспомогательный метод защитного копирования массива байтов с помощью обычного цикла for (стр. 6),
    // чтобы внешний код не мог изменить внутренние массивы состояния.
    private static byte[] copyArray(byte[] source)
    {
        if (source == null)
        {
            return new byte[0];
        }
        byte[] copy = new byte[source.length];
        for (int i = 0; i != source.length; i++)
        {
            copy[i] = source[i];
        }
        return copy;
    }
}

/**
 * Minimal non-cryptographic skeleton of the Crypto Gym application for Sheet 1
 * (Exercises 1.4 and 1.5, restricted to Chapter 1, pages 1-16).
 *
 * @author Daniel
 */
public class CryptoGymSheet1
{
    private final CryptoGymState state = new CryptoGymState();

    /**
     * Registers and verifies the Bouncy Castle JCA provider ({@code "BC"}) in the active JVM,
     * updating the application status field accordingly.
     */
    public void initProvider()
    {
        // Регистрируем провайдер Bouncy Castle в системе (стр. 3)
        Security.addProvider(new BouncyCastleProvider());

        // Проверяем наличие провайдера "BC", как в ListProviderCapabilities на стр. 7
        Provider provider = Security.getProvider("BC");

        if (provider != null)
        {
            // Записываем имя и описание провайдера в поле Status (как в ListProviders на стр. 6)
            this.state.setStatus("Provider ready: " + provider.getName() + " (" + provider.getInfo() + ")");
        }
        else
        {
            this.state.setStatus("Error: provider BC not found");
        }
    }

    /**
     * Sets the plaintext string and its raw byte representation in the model.
     *
     * @param text     human-readable plaintext string
     * @param rawBytes raw byte array representation of the plaintext
     */
    public void setPlaintext(String text, byte[] rawBytes)
    {
        this.state.setPlaintext(text, rawBytes);
        this.state.setStatus("Plaintext updated");
    }

    /**
     * Computes the length of the given byte array in raw bytes.
     *
     * @param data byte array to measure; may be {@code null}
     * @return number of bytes, or {@code 0} if {@code data} is {@code null}
     */
    public int getLengthInBytes(byte[] data)
    {
        if (data == null)
        {
            return 0;
        }
        return data.length;
    }

    /**
     * Resets the application state to its initial empty values.
     */
    public void reset()
    {
        this.state.reset();
    }

    /**
     * Prints the current state of all Crypto Gym fields and their byte lengths to standard output.
     */
    public void printDashboard()
    {
        System.out.println("=== Crypto Gym (Minimal Skeleton - Sheet 1) ===");
        System.out.println("Plaintext       : " + this.state.getPlaintext());
        System.out.println("Plaintext Bytes : " + getLengthInBytes(this.state.getPlaintextBytes()));
        System.out.println("Ciphertext Bytes: " + getLengthInBytes(this.state.getCiphertextBytes()));
        System.out.println("Key Bytes       : " + getLengthInBytes(this.state.getKeyBytes()));
        System.out.println("IV Bytes        : " + getLengthInBytes(this.state.getIvBytes()));
        System.out.println("Status          : " + this.state.getStatus());
        System.out.println();
    }

    /**
     * Demonstrates the minimal Sheet 1 skeleton.
     *
     * @param args command-line arguments (unused)
     */
    public static void main(String[] args)
    {
        CryptoGymSheet1 gym = new CryptoGymSheet1();
        gym.initProvider();
        gym.printDashboard();

        gym.setPlaintext("Test message 16b", new byte[16]);
        gym.printDashboard();

        gym.reset();
        gym.printDashboard();
    }
}
