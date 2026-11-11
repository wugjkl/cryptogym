package cryptogym;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Immutable Data Transfer Object (DTO) encapsulating all parameters for a block cipher
 * operation in Sheet 3 (Exercises 3.3 and 3.4, pages 25-33).
 * <p>
 * Constructed via {@link Builder} and enforces defensive copying on all sensitive byte arrays.
 * </p>
 *
 * @author Daniel
 */
final class BlockCipherRequest
{
    private final String algorithm;
    private final String mode;
    private final String padding;
    private final byte[] key;
    private final byte[] iv;
    private final byte[] data;

    private BlockCipherRequest(Builder builder)
    {
        this.algorithm = builder.algorithm;
        this.mode = builder.mode;
        this.padding = builder.padding;
        this.key = (builder.key != null) ? Arrays.copyOf(builder.key, builder.key.length) : new byte[0];
        this.iv = (builder.iv != null) ? Arrays.copyOf(builder.iv, builder.iv.length) : new byte[0];
        this.data = (builder.data != null) ? Arrays.copyOf(builder.data, builder.data.length) : new byte[0];
    }

    /**
     * Returns the JCA algorithm name (e.g., {@code "AES"}).
     *
     * @return non-null algorithm name
     */
    public String getAlgorithm()
    {
        return this.algorithm;
    }

    /**
     * Returns the block cipher mode (e.g., {@code "ECB"}, {@code "CBC"}, {@code "CTS"}).
     *
     * @return non-null mode string
     */
    public String getMode()
    {
        return this.mode;
    }

    /**
     * Returns the padding scheme name (e.g., {@code "PKCS7Padding"}, {@code "ISO7816-4Padding"}).
     *
     * @return non-null padding name
     */
    public String getPadding()
    {
        return this.padding;
    }

    /**
     * Returns a defensive copy of the secret key bytes.
     *
     * @return non-null copy of the secret key byte array
     */
    public byte[] getKey()
    {
        return Arrays.copyOf(this.key, this.key.length);
    }

    /**
     * Returns a defensive copy of the Initialization Vector (IV) bytes.
     *
     * @return non-null copy of the IV byte array
     */
    public byte[] getIv()
    {
        return Arrays.copyOf(this.iv, this.iv.length);
    }

    /**
     * Returns a defensive copy of the input payload bytes.
     *
     * @return non-null copy of the data byte array
     */
    public byte[] getData()
    {
        return Arrays.copyOf(this.data, this.data.length);
    }

    /**
     * Resolves the JCA transformation string, mapping {@code "CTS"} to {@code Algorithm/CBC/CTSPadding}
     * as specified in {@code CTSExample} (Hook &amp; Eaves, 2025, p. 32).
     *
     * @return non-null JCA transformation string
     */
    public String toTransformation()
    {
        if ("CTS".equals(this.mode))
        {
            return this.algorithm + "/CBC/CTSPadding";
        }
        return this.algorithm + "/" + this.mode + "/" + this.padding;
    }

    /**
     * Builder for constructing immutable {@link BlockCipherRequest} DTOs.
     *
     * @author Daniel
     */
    public static final class Builder
    {
        private String algorithm = "AES";
        private String mode = "CBC";
        private String padding = "PKCS7Padding";
        private byte[] key = new byte[0];
        private byte[] iv = new byte[0];
        private byte[] data = new byte[0];

        public Builder algorithm(String algorithm)
        {
            this.algorithm = algorithm;
            return this;
        }

        public Builder mode(String mode)
        {
            this.mode = mode;
            return this;
        }

        public Builder padding(String padding)
        {
            this.padding = padding;
            return this;
        }

        public Builder key(byte[] key)
        {
            this.key = (key != null) ? Arrays.copyOf(key, key.length) : new byte[0];
            return this;
        }

        public Builder iv(byte[] iv)
        {
            this.iv = (iv != null) ? Arrays.copyOf(iv, iv.length) : new byte[0];
            return this;
        }

        public Builder data(byte[] data)
        {
            this.data = (data != null) ? Arrays.copyOf(data, data.length) : new byte[0];
            return this;
        }

        public BlockCipherRequest build()
        {
            return new BlockCipherRequest(this);
        }
    }
}

/**
 * Immutable Data Transfer Object (DTO) representing the output of a block cipher operation
 * in Sheet 3 (Exercises 3.3 and 3.4).
 *
 * @author Daniel
 */
final class BlockCipherResult
{
    private final byte[] data;
    private final byte[] iv;
    private final int processedBytes;

    public BlockCipherResult(byte[] data, byte[] iv, int processedBytes)
    {
        this.data = (data != null) ? Arrays.copyOf(data, data.length) : new byte[0];
        this.iv = (iv != null) ? Arrays.copyOf(iv, iv.length) : new byte[0];
        this.processedBytes = processedBytes;
    }

    /**
     * Returns a defensive copy of the output bytes (ciphertext or unpadded plaintext).
     *
     * @return non-null copy of the output byte array
     */
    public byte[] getData()
    {
        return Arrays.copyOf(this.data, this.data.length);
    }

    /**
     * Returns a defensive copy of the Initialization Vector (IV) used or auto-generated.
     *
     * @return non-null copy of the IV byte array
     */
    public byte[] getIv()
    {
        return Arrays.copyOf(this.iv, this.iv.length);
    }

    /**
     * Returns the exact number of valid output bytes produced.
     *
     * @return non-negative byte count
     */
    public int getProcessedBytes()
    {
        return this.processedBytes;
    }
}

/**
 * Service interface defining the contract for symmetric block cipher encryption and decryption
 * with configurable modes (ECB, CBC, CTS) and padding schemes (Exercises 3.3 and 3.4).
 *
 * @author Daniel
 */
interface Sheet3CipherService
{
    /**
     * Encrypts the plaintext specified in {@code request}, automatically generating a random IV
     * via {@link Cipher#getIV()} if the mode requires an IV and none was provided.
     *
     * @param request immutable {@link BlockCipherRequest}
     * @return immutable {@link BlockCipherResult} containing ciphertext bytes and effective IV
     * @throws GeneralSecurityException if the key, IV, input length, or transformation is invalid
     */
    BlockCipherResult encrypt(BlockCipherRequest request) throws GeneralSecurityException;

    /**
     * Decrypts the ciphertext specified in {@code request} and removes any padding bytes,
     * slicing the output array to the exact unpadded length {@code len}.
     *
     * @param request immutable {@link BlockCipherRequest}
     * @return immutable {@link BlockCipherResult} containing exact unpadded plaintext bytes
     * @throws GeneralSecurityException if the key, IV, ciphertext, or padding is invalid
     */
    BlockCipherResult decrypt(BlockCipherRequest request) throws GeneralSecurityException;

    /**
     * Generates a random Initialization Vector (IV) of one block size for the given algorithm.
     *
     * @param algorithm JCA algorithm name (e.g., {@code "AES"})
     * @return random IV byte array
     * @throws GeneralSecurityException if the algorithm is not supported
     */
    byte[] generateRandomIv(String algorithm) throws GeneralSecurityException;
}

/**
 * Bouncy Castle implementation of {@link Sheet3CipherService} supporting ECB, CBC, and CTS modes
 * and all 6 padding methods from Hook &amp; Eaves (2025, pp. 25-33).
 *
 * @author Daniel
 */
class CryptoComponentSheet3 implements Sheet3CipherService
{
    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] generateRandomIv(String algorithm)
        throws GeneralSecurityException
    {
        // Получаем экземпляр шифра, чтобы узнать размер его блока через getBlockSize() (стр. 27)
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/NoPadding", "BC");
        // Создаем генератор криптографически стойких случайных чисел SecureRandom (стр. 17, 27)
        SecureRandom random = new SecureRandom();
        // Выделяем массив байтов под IV размером ровно в один блок шифра (стр. 27)
        byte[] iv = new byte[cipher.getBlockSize()];
        // Заполняем массив iv случайными байтами (стр. 27)
        random.nextBytes(iv);
        return iv;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BlockCipherResult encrypt(BlockCipherRequest request)
        throws GeneralSecurityException
    {
        // Создаем объект секретного ключа SecretKeySpec из сырых байтов (стр. 26, строка 15)
        SecretKeySpec key = new SecretKeySpec(request.getKey(), request.getAlgorithm());

        // Получаем объект Cipher по строке трансформации из провайдера "BC" (стр. 26, 30, 32)
        Cipher cipher = Cipher.getInstance(request.toTransformation(), "BC");

        byte[] input = request.getData();
        byte[] usedIv = new byte[0];

        // В режиме ECB вектор инициализации не используется (стр. 24)
        if ("ECB".equals(request.getMode()))
        {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        else
        {
            // Для режимов CBC и CTS нужен вектор инициализации IV (стр. 26–28, 32).
            byte[] providedIv = request.getIv();
            if (providedIv.length > 0)
            {
                // Если IV передан в запросе — инициализируем через IvParameterSpec (как в CBCExample на стр. 27)
                cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(providedIv));
                usedIv = providedIv;
            }
            else
            {
                // Если IV не передан — шифр генерирует случайный IV сам, и мы забираем его через cipher.getIV(),
                // точно как в CBCGenExample на стр. 28 (строки 24–26)!
                cipher.init(Cipher.ENCRYPT_MODE, key);
                usedIv = cipher.getIV();
            }
        }

        // Выполняем шифрование открытого текста методом doFinal(input), как на стр. 27, 31 и 32
        byte[] output = cipher.doFinal(input);
        return new BlockCipherResult(output, usedIv, output.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BlockCipherResult decrypt(BlockCipherRequest request)
        throws GeneralSecurityException
    {
        // Создаем SecretKeySpec для выбранного алгоритма (стр. 30, строка 16)
        SecretKeySpec key = new SecretKeySpec(request.getKey(), request.getAlgorithm());

        // Получаем экземпляр Cipher из провайдера "BC" (стр. 30, строка 18)
        Cipher cipher = Cipher.getInstance(request.toTransformation(), "BC");

        byte[] output = request.getData();
        byte[] usedIv = request.getIv();

        // Инициализируем шифр в режиме расшифрования (Cipher.DECRYPT_MODE)
        if ("ECB".equals(request.getMode()))
        {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        else
        {
            // Для CBC и CTS обязательно передаем вектор инициализации через IvParameterSpec(iv) (стр. 29, 31, 32)
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(usedIv));
        }

        // Выделяем выходной массив finalOutput с помощью cipher.getOutputSize(output.length),
        // точно как в CBCPadExample на стр. 31 (строка 31) и CTSExample на стр. 32 (строка 34).
        byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];

        // Обрабатываем основные блоки через cipher.update() и сохраняем число записанных байтов в len (стр. 31, строка 33)
        int len = cipher.update(output, 0, output.length, finalOutput, 0);

        // Завершаем расшифрование и снимаем паддинг вызовом cipher.doFinal(finalOutput, len) (стр. 31, строка 35)
        len += cipher.doFinal(finalOutput, len);

        // Обрезаем массив finalOutput строго по реальной длине len через Arrays.copyOfRange(finalOutput, 0, len),
        // чтобы отсечь неиспользованные нулевые байты буфера (стр. 31, строка 37).
        byte[] actualPlaintext = Arrays.copyOfRange(finalOutput, 0, len);

        return new BlockCipherResult(actualPlaintext, usedIv, len);
    }
}

/**
 * Controller and demonstration harness for Sheet 3 Crypto Gym (Exercises 3.3 and 3.4).
 *
 * @author Daniel
 */
public class CryptoGymSheet3
{
    private String algorithm = "AES";
    private String mode = "CBC";
    private String padding = "PKCS7Padding";

    private byte[] keyBytes = new byte[0];
    private byte[] ivBytes = new byte[0];
    private byte[] plaintextBytes = new byte[0];
    private byte[] ciphertextBytes = new byte[0];
    private String status = "Ready";

    private final Sheet3CipherService crypto = new CryptoComponentSheet3();

    /**
     * Constructs the controller and ensures the Bouncy Castle provider is registered.
     */
    public CryptoGymSheet3()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Configures the block cipher mode and padding scheme.
     *
     * @param mode    block cipher mode ({@code "ECB"}, {@code "CBC"}, {@code "CTS"})
     * @param padding padding scheme name from pages 29-30
     */
    public void configure(String mode, String padding)
    {
        this.mode = mode;
        this.padding = padding;
        this.status = "Configured: " + this.algorithm + "/" + this.mode + "/" + this.padding;
    }

    /**
     * Sets the secret key from a hexadecimal string.
     *
     * @param keyHex secret key in hex format
     */
    public void setKeyHex(String keyHex)
    {
        this.keyBytes = (keyHex != null && keyHex.length() > 0) ? Hex.decode(keyHex) : new byte[0];
    }

    /**
     * Sets the Initialization Vector (IV) from a hexadecimal string.
     *
     * @param ivHex IV in hex format, or empty string to trigger auto-generation during encryption
     */
    public void setIvHex(String ivHex)
    {
        this.ivBytes = (ivHex != null && ivHex.length() > 0) ? Hex.decode(ivHex) : new byte[0];
    }

    /**
     * Sets the plaintext payload from a hexadecimal string.
     *
     * @param plaintextHex plaintext in hex format
     */
    public void setPlaintextHex(String plaintextHex)
    {
        this.plaintextBytes = (plaintextHex != null && plaintextHex.length() > 0)
            ? Hex.decode(plaintextHex)
            : new byte[0];
    }

    /**
     * Executes encryption using the current configuration and updates ciphertext and IV bytes.
     */
    public void onEncrypt()
    {
        try
        {
            BlockCipherRequest req = new BlockCipherRequest.Builder()
                .algorithm(this.algorithm)
                .mode(this.mode)
                .padding(this.padding)
                .key(this.keyBytes)
                .iv(this.ivBytes)
                .data(this.plaintextBytes)
                .build();

            BlockCipherResult result = this.crypto.encrypt(req);
            this.ciphertextBytes = result.getData();
            this.ivBytes = result.getIv();
            this.status = "Encrypted with " + req.toTransformation()
                          + " (" + result.getProcessedBytes() + " bytes)";
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            this.status = "Encrypt Error: " + e.getMessage();
        }
    }

    /**
     * Executes decryption using the current configuration and updates plaintext bytes.
     */
    public void onDecrypt()
    {
        try
        {
            BlockCipherRequest req = new BlockCipherRequest.Builder()
                .algorithm(this.algorithm)
                .mode(this.mode)
                .padding(this.padding)
                .key(this.keyBytes)
                .iv(this.ivBytes)
                .data(this.ciphertextBytes)
                .build();

            BlockCipherResult result = this.crypto.decrypt(req);
            this.plaintextBytes = result.getData();
            this.status = "Decrypted with " + req.toTransformation()
                          + " (" + result.getProcessedBytes() + " bytes)";
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            this.status = "Decrypt Error: " + e.getMessage();
        }
    }

    /**
     * Prints the current state of all fields and their raw byte lengths.
     */
    public void printState()
    {
        System.out.println("------------------------------------------------------------");
        System.out.println("Status          : " + this.status);
        System.out.println("Key (Hex)       : " + Hex.toHexString(this.keyBytes)
                           + " (" + this.keyBytes.length + " bytes)");
        System.out.println("IV (Hex)        : " + Hex.toHexString(this.ivBytes)
                           + " (" + this.ivBytes.length + " bytes)");
        System.out.println("Plaintext (Hex) : " + Hex.toHexString(this.plaintextBytes)
                           + " (" + this.plaintextBytes.length + " bytes)");
        System.out.println("Ciphertext (Hex): " + Hex.toHexString(this.ciphertextBytes)
                           + " (" + this.ciphertextBytes.length + " bytes)");
    }

    /**
     * Demonstrates all 6 padding schemes (Exercise 3.3) and CBC/CTS modes (Exercise 3.4).
     *
     * @param args command-line arguments (unused)
     */
    public static void main(String[] args)
    {
        CryptoGymSheet3 gym = new CryptoGymSheet3();

        String testKey = "000102030405060708090a0b0c0d0e0f";
        String testIv  = "0102030405060708090a0b0c0d0e0f10";
        String testInput24Bytes = "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7";

        String[] paddings = new String[] {
            "ISO7816-4Padding",
            "ISO10126-2Padding",
            "PKCS7Padding",
            "TBCPadding",
            "X9.23Padding",
            "ZeroBytePadding"
        };

        System.out.println("=== 1. TESTING ALL PADDING METHODS IN CBC MODE (Ex. 3.3) ===");
        for (int i = 0; i != paddings.length; i++)
        {
            gym.setKeyHex(testKey);
            gym.setIvHex(testIv);
            gym.setPlaintextHex(testInput24Bytes);
            gym.configure("CBC", paddings[i]);

            gym.onEncrypt();
            gym.onDecrypt();
            gym.printState();
        }

        System.out.println("\n=== 2. TESTING CTS MODE - CIPHER TEXT STEALING (Ex. 3.4) ===");
        gym.setKeyHex(testKey);
        gym.setIvHex("");
        gym.setPlaintextHex(testInput24Bytes);
        gym.configure("CTS", "CTSPadding");

        gym.onEncrypt();
        gym.onDecrypt();
        gym.printState();
    }
}
