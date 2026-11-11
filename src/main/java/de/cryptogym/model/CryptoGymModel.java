package de.cryptogym.model;

import java.util.Arrays;
import java.util.Objects;
import de.cryptogym.domain.BlockCipherMode;
import de.cryptogym.domain.CipherAlgorithm;
import de.cryptogym.domain.PaddingScheme;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Encapsulated Model in the MVC architecture representing the state of the Crypto Gym application.
 * <p>
 * Guarantees that all sensitive raw byte arrays (keys, IVs, plaintext, ciphertext) are stored
 * privately and accessed exclusively via defensive copies. Automatically maintains raw byte length
 * counters as required by the Crypto Gym specification ({@code cg-req.pdf}).
 * </p>
 *
 * @author Daniel
 */
public class CryptoGymModel
{
    private CipherAlgorithm algorithm = CipherAlgorithm.AES;
    private BlockCipherMode mode = BlockCipherMode.CBC;
    private PaddingScheme padding = PaddingScheme.PKCS7;

    private String plaintextString = "";
    private byte[] plaintextBytes = new byte[0];
    private byte[] ciphertextBytes = new byte[0];
    private byte[] keyBytes = new byte[0];
    private byte[] ivBytes = new byte[0];
    private String status = "Ready";

    /**
     * Returns the selected symmetric block cipher algorithm.
     *
     * @return non-null {@link CipherAlgorithm}
     */
    public CipherAlgorithm getAlgorithm()
    {
        return this.algorithm;
    }

    /**
     * Sets the active symmetric block cipher algorithm.
     *
     * @param algorithm non-null {@link CipherAlgorithm}
     */
    public void setAlgorithm(CipherAlgorithm algorithm)
    {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
    }

    /**
     * Returns the selected block cipher mode of operation.
     *
     * @return non-null {@link BlockCipherMode}
     */
    public BlockCipherMode getMode()
    {
        return this.mode;
    }

    /**
     * Sets the active block cipher mode of operation.
     *
     * @param mode non-null {@link BlockCipherMode}
     */
    public void setMode(BlockCipherMode mode)
    {
        this.mode = Objects.requireNonNull(mode, "mode must not be null");
    }

    /**
     * Returns the selected padding scheme.
     *
     * @return non-null {@link PaddingScheme}
     */
    public PaddingScheme getPadding()
    {
        return this.padding;
    }

    /**
     * Sets the active padding scheme.
     *
     * @param padding non-null {@link PaddingScheme}
     */
    public void setPadding(PaddingScheme padding)
    {
        this.padding = Objects.requireNonNull(padding, "padding must not be null");
    }

    /**
     * Returns the textual representation of the plaintext.
     *
     * @return non-null plaintext string
     */
    public String getPlaintextString()
    {
        return this.plaintextString;
    }

    /**
     * Updates the plaintext from a character string and synchronizes the underlying raw byte array.
     *
     * @param text plaintext string; if {@code null}, treated as empty string
     */
    public void setPlaintextFromString(String text)
    {
        this.plaintextString = (text != null) ? text : "";
        this.plaintextBytes = Strings.toByteArray(this.plaintextString);
    }

    /**
     * Returns a defensive copy of the raw plaintext bytes.
     *
     * @return non-null copy of the plaintext byte array
     */
    public byte[] getPlaintextBytes()
    {
        return Arrays.copyOf(this.plaintextBytes, this.plaintextBytes.length);
    }

    /**
     * Updates the raw plaintext bytes (defensively copied) and synchronizes the string representation.
     *
     * @param bytes plaintext byte array; if {@code null}, resets to empty array
     */
    public void setPlaintextBytes(byte[] bytes)
    {
        this.plaintextBytes = (bytes != null) ? Arrays.copyOf(bytes, bytes.length) : new byte[0];
        this.plaintextString = Strings.fromByteArray(this.plaintextBytes);
    }

    /**
     * Returns the hexadecimal representation of the raw plaintext bytes.
     *
     * @return non-null lowercase hex string
     */
    public String getPlaintextHex()
    {
        return Hex.toHexString(this.plaintextBytes);
    }

    /**
     * Updates the plaintext from a hexadecimal string.
     *
     * @param hex valid hex string; if {@code null} or empty, resets to empty byte array
     */
    public void setPlaintextHex(String hex)
    {
        byte[] decoded = decodeHexSafely(hex);
        setPlaintextBytes(decoded);
    }

    /**
     * Returns the length of the plaintext in raw bytes.
     *
     * @return non-negative byte count
     */
    public int getPlaintextLengthInBytes()
    {
        return this.plaintextBytes.length;
    }

    /**
     * Returns a defensive copy of the raw ciphertext bytes.
     *
     * @return non-null copy of the ciphertext byte array
     */
    public byte[] getCiphertextBytes()
    {
        return Arrays.copyOf(this.ciphertextBytes, this.ciphertextBytes.length);
    }

    /**
     * Updates the raw ciphertext bytes (defensively copied).
     *
     * @param bytes ciphertext byte array; if {@code null}, resets to empty array
     */
    public void setCiphertextBytes(byte[] bytes)
    {
        this.ciphertextBytes = (bytes != null) ? Arrays.copyOf(bytes, bytes.length) : new byte[0];
    }

    /**
     * Returns the hexadecimal representation of the ciphertext bytes.
     *
     * @return non-null lowercase hex string
     */
    public String getCiphertextHex()
    {
        return Hex.toHexString(this.ciphertextBytes);
    }

    /**
     * Updates the ciphertext from a hexadecimal string.
     *
     * @param hex valid hex string; if {@code null} or empty, resets to empty byte array
     */
    public void setCiphertextHex(String hex)
    {
        this.ciphertextBytes = decodeHexSafely(hex);
    }

    /**
     * Returns the length of the ciphertext in raw bytes.
     *
     * @return non-negative byte count
     */
    public int getCiphertextLengthInBytes()
    {
        return this.ciphertextBytes.length;
    }

    /**
     * Returns a defensive copy of the secret key bytes.
     *
     * @return non-null copy of the key byte array
     */
    public byte[] getKeyBytes()
    {
        return Arrays.copyOf(this.keyBytes, this.keyBytes.length);
    }

    /**
     * Updates the secret key bytes (defensively copied).
     *
     * @param bytes secret key byte array; if {@code null}, resets to empty array
     */
    public void setKeyBytes(byte[] bytes)
    {
        this.keyBytes = (bytes != null) ? Arrays.copyOf(bytes, bytes.length) : new byte[0];
    }

    /**
     * Returns the hexadecimal representation of the secret key.
     *
     * @return non-null lowercase hex string
     */
    public String getKeyHex()
    {
        return Hex.toHexString(this.keyBytes);
    }

    /**
     * Updates the secret key from a hexadecimal string.
     *
     * @param hex valid hex string; if {@code null} or empty, resets to empty byte array
     */
    public void setKeyHex(String hex)
    {
        this.keyBytes = decodeHexSafely(hex);
    }

    /**
     * Returns the length of the secret key in raw bytes.
     *
     * @return non-negative byte count
     */
    public int getKeyLengthInBytes()
    {
        return this.keyBytes.length;
    }

    /**
     * Returns a defensive copy of the Initialization Vector (IV) bytes.
     *
     * @return non-null copy of the IV byte array
     */
    public byte[] getIvBytes()
    {
        return Arrays.copyOf(this.ivBytes, this.ivBytes.length);
    }

    /**
     * Updates the Initialization Vector (IV) bytes (defensively copied).
     *
     * @param bytes IV byte array; if {@code null}, resets to empty array
     */
    public void setIvBytes(byte[] bytes)
    {
        this.ivBytes = (bytes != null) ? Arrays.copyOf(bytes, bytes.length) : new byte[0];
    }

    /**
     * Returns the hexadecimal representation of the Initialization Vector (IV).
     *
     * @return non-null lowercase hex string
     */
    public String getIvHex()
    {
        return Hex.toHexString(this.ivBytes);
    }

    /**
     * Updates the Initialization Vector (IV) from a hexadecimal string.
     *
     * @param hex valid hex string; if {@code null} or empty, resets to empty byte array
     */
    public void setIvHex(String hex)
    {
        this.ivBytes = decodeHexSafely(hex);
    }

    /**
     * Returns the length of the Initialization Vector (IV) in raw bytes.
     *
     * @return non-negative byte count
     */
    public int getIvLengthInBytes()
    {
        return this.ivBytes.length;
    }

    /**
     * Returns the current status or error message.
     *
     * @return non-null status string
     */
    public String getStatus()
    {
        return this.status;
    }

    /**
     * Updates the status message.
     *
     * @param status new status description
     */
    public void setStatus(String status)
    {
        this.status = (status != null) ? status : "";
    }

    /**
     * Resets all sensitive byte arrays, text fields, and status to their initial state.
     * Zeroizes existing arrays in memory before discarding references.
     */
    public void reset()
    {
        Arrays.fill(this.plaintextBytes, (byte) 0);
        Arrays.fill(this.ciphertextBytes, (byte) 0);
        Arrays.fill(this.keyBytes, (byte) 0);
        Arrays.fill(this.ivBytes, (byte) 0);

        this.plaintextString = "";
        this.plaintextBytes = new byte[0];
        this.ciphertextBytes = new byte[0];
        this.keyBytes = new byte[0];
        this.ivBytes = new byte[0];
        this.status = "Reset to initial state";
    }

    private byte[] decodeHexSafely(String hex)
    {
        if (hex == null || hex.trim().isEmpty())
        {
            return new byte[0];
        }
        return Hex.decode(hex.trim());
    }
}
