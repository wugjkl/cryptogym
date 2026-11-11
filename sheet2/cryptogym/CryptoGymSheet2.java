package cryptogym;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Immutable Data Transfer Object (DTO) encapsulating the parameters for an ECB cipher operation
 * in Sheet 2 (Exercise 2.3, pages 16-25).
 * <p>
 * Constructed via {@link Builder} and enforces defensive copying on byte arrays.
 * </p>
 *
 * @author Daniel
 */
final class EcbCipherRequest
{
    private final String algorithm;
    private final byte[] keyBytes;
    private final byte[] dataBytes;

    private EcbCipherRequest(Builder builder)
    {
        this.algorithm = builder.algorithm;
        this.keyBytes = copyBytes(builder.keyBytes);
        this.dataBytes = copyBytes(builder.dataBytes);
    }

    /**
     * Returns the JCA algorithm name (e.g., {@code "AES"} or {@code "DES"}).
     *
     * @return non-null algorithm identifier
     */
    public String getAlgorithm()
    {
        return this.algorithm;
    }

    /**
     * Returns a defensive copy of the secret key bytes.
     *
     * @return non-null key byte array
     */
    public byte[] getKeyBytes()
    {
        return copyBytes(this.keyBytes);
    }

    /**
     * Returns a defensive copy of the input payload bytes.
     *
     * @return non-null payload byte array
     */
    public byte[] getDataBytes()
    {
        return copyBytes(this.dataBytes);
    }

    static byte[] copyBytes(byte[] src)
    {
        if (src == null)
        {
            return new byte[0];
        }
        byte[] copy = new byte[src.length];
        for (int i = 0; i != src.length; i++)
        {
            copy[i] = src[i];
        }
        return copy;
    }

    /**
     * Builder for constructing immutable {@link EcbCipherRequest} instances.
     *
     * @author Daniel
     */
    public static final class Builder
    {
        private String algorithm = "AES";
        private byte[] keyBytes = new byte[0];
        private byte[] dataBytes = new byte[0];

        /**
         * Sets the target block cipher algorithm name.
         *
         * @param algorithm JCA algorithm name (e.g., {@code "AES"})
         * @return this builder instance
         */
        public Builder algorithm(String algorithm)
        {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Sets the raw secret key bytes.
         *
         * @param keyBytes secret key byte array
         * @return this builder instance
         */
        public Builder keyBytes(byte[] keyBytes)
        {
            this.keyBytes = copyBytes(keyBytes);
            return this;
        }

        /**
         * Sets the raw input data bytes (plaintext or ciphertext).
         *
         * @param dataBytes input payload byte array
         * @return this builder instance
         */
        public Builder dataBytes(byte[] dataBytes)
        {
            this.dataBytes = copyBytes(dataBytes);
            return this;
        }

        /**
         * Builds the immutable {@link EcbCipherRequest}.
         *
         * @return configured {@link EcbCipherRequest}
         */
        public EcbCipherRequest build()
        {
            return new EcbCipherRequest(this);
        }
    }
}

/**
 * Service interface defining the contract for the extensible Crypto Gym cryptographic component
 * in Sheet 2 (Exercise 2.3).
 *
 * @author Daniel
 */
interface Sheet2CipherService
{
    /**
     * Encrypts the block-aligned plaintext specified in the request using ECB mode without padding.
     *
     * @param request immutable {@link EcbCipherRequest} containing algorithm, key, and plaintext bytes
     * @return encrypted ciphertext byte array
     * @throws GeneralSecurityException if the algorithm, provider, key size, or block alignment is invalid
     */
    byte[] encrypt(EcbCipherRequest request) throws GeneralSecurityException;

    /**
     * Decrypts the block-aligned ciphertext specified in the request using ECB mode without padding.
     *
     * @param request immutable {@link EcbCipherRequest} containing algorithm, key, and ciphertext bytes
     * @return decrypted plaintext byte array
     * @throws GeneralSecurityException if the algorithm, provider, key size, or block alignment is invalid
     */
    byte[] decrypt(EcbCipherRequest request) throws GeneralSecurityException;

    /**
     * Generates a new random secret key for the specified algorithm and bit length.
     *
     * @param algorithm  JCA algorithm identifier (e.g., {@code "AES"})
     * @param keyBitSize key length in bits (e.g., 128)
     * @return encoded secret key bytes
     * @throws GeneralSecurityException if the algorithm or key size is unsupported
     */
    byte[] generateKeyBytes(String algorithm, int keyBitSize) throws GeneralSecurityException;
}

/**
 * Bouncy Castle implementation of {@link Sheet2CipherService} based on {@code ECBShortExample}
 * (Hook &amp; Eaves, 2025, p. 24).
 *
 * @author Daniel
 */
class CryptoComponentSheet2 implements Sheet2CipherService
{
    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] generateKeyBytes(String algorithm, int keyBitSize)
        throws GeneralSecurityException
    {
        // Создаем генератор ключей для выбранного алгоритма из провайдера BC (стр. 23)
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm, "BC");
        // Инициализируем генератор длиной ключа в битах (стр. 23)
        keyGen.init(keyBitSize);
        // Генерируем секретный ключ и возвращаем его байты через getEncoded() (стр. 23)
        Key key = keyGen.generateKey();
        return key.getEncoded();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(EcbCipherRequest request)
        throws GeneralSecurityException
    {
        // Оборачиваем сырые байты ключа в SecretKeySpec для выбранного алгоритма (стр. 22, 24)
        SecretKeySpec key = new SecretKeySpec(request.getKeyBytes(), request.getAlgorithm());
        // Получаем экземпляр шифра в режиме ECB/NoPadding из провайдера BC (стр. 24, строка 16)
        Cipher cipher = Cipher.getInstance(request.getAlgorithm() + "/ECB/NoPadding", "BC");
        // Инициализируем шифр на шифрование (ENCRYPT_MODE) с ключом key (стр. 24, строка 22)
        cipher.init(Cipher.ENCRYPT_MODE, key);
        // Шифруем массив входных байтов за один вызов doFinal() (стр. 24, строка 24)
        return cipher.doFinal(request.getDataBytes());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(EcbCipherRequest request)
        throws GeneralSecurityException
    {
        // Оборачиваем сырые байты ключа в SecretKeySpec (стр. 24, строка 14)
        SecretKeySpec key = new SecretKeySpec(request.getKeyBytes(), request.getAlgorithm());
        // Получаем экземпляр шифра в режиме ECB/NoPadding (стр. 24, строка 16)
        Cipher cipher = Cipher.getInstance(request.getAlgorithm() + "/ECB/NoPadding", "BC");
        // Инициализируем шифр на расшифрование (DECRYPT_MODE) с ключом key (стр. 24, строка 28)
        cipher.init(Cipher.DECRYPT_MODE, key);
        // Расшифровываем данные через doFinal() (стр. 24, строки 30–31)
        return cipher.doFinal(request.getDataBytes());
    }
}

/**
 * Controller and demonstration harness for the Sheet 2 Crypto Gym application (Exercise 2.3).
 *
 * @author Daniel
 */
public class CryptoGymSheet2
{
    private String algorithm = "AES";
    private byte[] plaintextBytes = new byte[0];
    private byte[] ciphertextBytes = new byte[0];
    private byte[] keyBytes = new byte[0];
    private String status = "Ready";

    private final Sheet2CipherService crypto = new CryptoComponentSheet2();

    /**
     * Constructs the Crypto Gym controller and registers the Bouncy Castle provider.
     */
    public CryptoGymSheet2()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Sets the plaintext from a character string using {@link Strings#toByteArray(String)} (p. 17).
     *
     * @param text plaintext string
     */
    public void setPlaintextFromString(String text)
    {
        this.plaintextBytes = Strings.toByteArray(text);
        this.status = "Plaintext set from string";
    }

    /**
     * Sets the plaintext from a hexadecimal string using {@link Hex#decode(String)} (p. 24).
     *
     * @param hex hexadecimal plaintext string
     */
    public void setPlaintextHex(String hex)
    {
        this.plaintextBytes = (hex != null && hex.length() != 0) ? Hex.decode(hex) : new byte[0];
        this.status = "Plaintext set from Hex";
    }

    /**
     * Sets the secret key from a hexadecimal string using {@link Hex#decode(String)} (p. 24).
     *
     * @param hex hexadecimal key string
     */
    public void setKeyHex(String hex)
    {
        this.keyBytes = (hex != null && hex.length() != 0) ? Hex.decode(hex) : new byte[0];
        this.status = "Key updated";
    }

    /**
     * Encrypts the current plaintext bytes and updates the ciphertext and status fields.
     */
    public void onEncryptButton()
    {
        try
        {
            EcbCipherRequest req = new EcbCipherRequest.Builder()
                .algorithm(this.algorithm)
                .keyBytes(this.keyBytes)
                .dataBytes(this.plaintextBytes)
                .build();
            this.ciphertextBytes = this.crypto.encrypt(req);
            this.status = "Encryption successful (" + this.algorithm + "/ECB/NoPadding)";
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            this.status = "Encryption error: " + e.getMessage();
        }
    }

    /**
     * Decrypts the current ciphertext bytes and updates the plaintext and status fields.
     */
    public void onDecryptButton()
    {
        try
        {
            EcbCipherRequest req = new EcbCipherRequest.Builder()
                .algorithm(this.algorithm)
                .keyBytes(this.keyBytes)
                .dataBytes(this.ciphertextBytes)
                .build();
            this.plaintextBytes = this.crypto.decrypt(req);
            this.status = "Decryption successful (" + this.algorithm + "/ECB/NoPadding)";
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            this.status = "Decryption error: " + e.getMessage();
        }
    }

    /**
     * Resets all fields in the controller to their initial empty state.
     */
    public void onResetButton()
    {
        this.plaintextBytes = new byte[0];
        this.ciphertextBytes = new byte[0];
        this.keyBytes = new byte[0];
        this.status = "Reset complete";
    }

    /**
     * Prints the current state of the Crypto Gym fields and their lengths in raw bytes.
     */
    public void printState()
    {
        System.out.println("=== Crypto Gym (Sheet 2 - AES/ECB Component) ===");
        System.out.println("Algorithm        : " + this.algorithm);
        System.out.println("Key (Hex)        : " + Hex.toHexString(this.keyBytes)
                           + " [" + this.keyBytes.length + " bytes]");
        System.out.println("Plaintext (Hex)  : " + Hex.toHexString(this.plaintextBytes)
                           + " [" + this.plaintextBytes.length + " bytes]");
        System.out.println("Ciphertext (Hex) : " + Hex.toHexString(this.ciphertextBytes)
                           + " [" + this.ciphertextBytes.length + " bytes]");
        System.out.println("Status           : " + this.status);
        System.out.println();
    }

    /**
     * Demonstrates encryption and decryption using the test vectors from {@code ECBShortExample} (p. 24).
     *
     * @param args command-line arguments (unused)
     */
    public static void main(String[] args)
    {
        CryptoGymSheet2 gym = new CryptoGymSheet2();
        gym.setKeyHex("000102030405060708090a0b0c0d0e0f");
        gym.setPlaintextHex("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        gym.onEncryptButton();
        gym.printState();

        gym.setPlaintextHex("");
        gym.onDecryptButton();
        gym.printState();
    }
}
