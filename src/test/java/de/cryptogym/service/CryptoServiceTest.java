package de.cryptogym.service;

import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import de.cryptogym.domain.BlockCipherMode;
import de.cryptogym.domain.CipherAlgorithm;
import de.cryptogym.domain.CryptoOperationException;
import de.cryptogym.domain.CryptoRequest;
import de.cryptogym.domain.CryptoResponse;
import de.cryptogym.domain.PaddingScheme;
import de.cryptogym.domain.SymmetricCipherSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit, Known Answer (KAT), Parameterized, and Negative test suite for {@link SymmetricCipherService}
 * covering Exercises 1.4, 2.2, 2.3, 3.2, 3.3, and 3.4.
 *
 * @author Daniel
 */
class CryptoServiceTest
{
    private SymmetricCipherService cipherService;

    private static final byte[] BOOK_AES_KEY = Hex.decode("000102030405060708090a0b0c0d0e0f");
    private static final byte[] BOOK_AES_IV  = Hex.decode("0102030405060708090a0b0c0d0e0f10");
    private static final byte[] BOOK_INPUT_16B = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");
    private static final byte[] BOOK_INPUT_24B = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");
    private static final byte[] BOOK_INPUT_32B = Hex.decode(
        "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
    );

    @BeforeEach
    void setUp()
    {
        this.cipherService = CipherServiceFactory.createSymmetricCipherService();
    }

    // =========================================================================
    // 1. KNOWN ANSWER TESTS (KAT) - NIST SP 800-38A & Hook/Eaves Book Vectors
    // =========================================================================

    /**
     * Verifies AES-128-ECB encryption and decryption against official NIST SP 800-38A F.1.1 test vectors.
     *
     * @throws CryptoOperationException if cipher operation fails unexpectedly
     */
    @Test
    @DisplayName("KAT: NIST SP 800-38A AES-128-ECB Known Answer Test")
    void testNistAes128EcbKnownAnswer() throws CryptoOperationException
    {
        byte[] nistKey = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] nistPlaintext = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
        byte[] expectedCiphertext = Hex.decode("3ad77bb40d7a3660a89ecaf32466ef97");

        SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.ECB)
            .padding(PaddingScheme.NO_PADDING)
            .build();

        CryptoRequest encryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(nistKey)
            .data(nistPlaintext)
            .build();

        CryptoResponse encryptRes = this.cipherService.encrypt(encryptReq);
        assertArrayEquals(expectedCiphertext, encryptRes.getData(), "NIST AES-128-ECB ciphertext mismatch");

        CryptoRequest decryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(nistKey)
            .data(encryptRes.getData())
            .build();

        CryptoResponse decryptRes = this.cipherService.decrypt(decryptReq);
        assertArrayEquals(nistPlaintext, decryptRes.getData(), "NIST AES-128-ECB decrypted plaintext mismatch");
    }

    /**
     * Verifies AES-128-CBC encryption and decryption against official NIST SP 800-38A F.2.1 test vectors.
     *
     * @throws CryptoOperationException if cipher operation fails unexpectedly
     */
    @Test
    @DisplayName("KAT: NIST SP 800-38A AES-128-CBC Known Answer Test")
    void testNistAes128CbcKnownAnswer() throws CryptoOperationException
    {
        byte[] nistKey = Hex.decode("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] nistIv  = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] nistPlaintext = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
        byte[] expectedCiphertext = Hex.decode("7649abac8119b246cee98e9b12e9197d");

        SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.CBC)
            .padding(PaddingScheme.NO_PADDING)
            .build();

        CryptoRequest encryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(nistKey)
            .iv(nistIv)
            .data(nistPlaintext)
            .build();

        CryptoResponse encryptRes = this.cipherService.encrypt(encryptReq);
        assertArrayEquals(expectedCiphertext, encryptRes.getData(), "NIST AES-128-CBC ciphertext mismatch");

        CryptoRequest decryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(nistKey)
            .iv(nistIv)
            .data(encryptRes.getData())
            .build();

        CryptoResponse decryptRes = this.cipherService.decrypt(decryptReq);
        assertArrayEquals(nistPlaintext, decryptRes.getData(), "NIST AES-128-CBC decrypted plaintext mismatch");
    }

    // =========================================================================
    // 2. PARAMETERIZED TESTS - Exercise 2.2 (DES Weak Keys) & 3.3 (All Paddings)
    // =========================================================================

    /**
     * Verifies the involution property {@code E_K(E_K(P)) == P} for all four classic DES weak keys
     * (Exercise 2.2).
     *
     * @param weakKeyHex hexadecimal representation of the 64-bit DES weak key
     * @throws CryptoOperationException if cipher operation fails unexpectedly
     */
    @ParameterizedTest(name = "DES Weak Key [{index}]: {0}")
    @ValueSource(strings = {
        "0101010101010101",
        "fefefefefefefefe",
        "1f1f1f1f0e0e0e0e",
        "e0e0e0e0f1f1f1f1"
    })
    @DisplayName("Exercise 2.2: DES Weak Keys Involution Property E_K(E_K(P)) == P")
    void testDesWeakKeysInvolutionProperty(String weakKeyHex) throws CryptoOperationException
    {
        byte[] weakKey = Hex.decode(weakKeyHex);
        SymmetricCipherSpec desSpec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.DES)
            .mode(BlockCipherMode.ECB)
            .padding(PaddingScheme.NO_PADDING)
            .build();

        CryptoRequest firstEncryption = CryptoRequest.builder()
            .spec(desSpec)
            .key(weakKey)
            .data(BOOK_INPUT_16B)
            .build();
        CryptoResponse firstResult = this.cipherService.encrypt(firstEncryption);

        // Encrypt the ciphertext a SECOND time in ENCRYPT_MODE with the same weak key
        CryptoRequest secondEncryption = CryptoRequest.builder()
            .spec(desSpec)
            .key(weakKey)
            .data(firstResult.getData())
            .build();
        CryptoResponse secondResult = this.cipherService.encrypt(secondEncryption);

        assertArrayEquals(
            BOOK_INPUT_16B,
            secondResult.getData(),
            "Encrypting twice with DES weak key " + weakKeyHex + " must reproduce original plaintext"
        );
    }

    /**
     * Verifies encryption and decryption round-trip for all 6 padding methods from Exercise 3.3
     * on non-block-aligned 24-byte input, ensuring no trailing zero bytes remain (Exercise 3.2a).
     *
     * @param padding padding scheme under test
     * @throws CryptoOperationException if cipher operation fails unexpectedly
     */
    @ParameterizedTest(name = "CBC Padding [{index}]: {0}")
    @EnumSource(
        value = PaddingScheme.class,
        names = { "ISO7816_4", "ISO10126_2", "PKCS7", "PKCS5", "TBC", "X9_23", "ZERO_BYTE" }
    )
    @DisplayName("Exercise 3.3 & 3.2a: All 6 Paddings Round-Trip Without Trailing Null Bytes")
    void testAllPaddingSchemesRoundTrip24Bytes(PaddingScheme padding) throws CryptoOperationException
    {
        SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.CBC)
            .padding(padding)
            .build();

        CryptoRequest encryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(BOOK_AES_KEY)
            .iv(BOOK_AES_IV)
            .data(BOOK_INPUT_24B)
            .build();

        CryptoResponse encryptRes = this.cipherService.encrypt(encryptReq);
        assertEquals(32, encryptRes.getProcessedBytes(), "Padded 24-byte input must expand to 32 bytes (2 AES blocks)");

        CryptoRequest decryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(BOOK_AES_KEY)
            .iv(BOOK_AES_IV)
            .data(encryptRes.getData())
            .build();

        CryptoResponse decryptRes = this.cipherService.decrypt(decryptReq);
        assertEquals(24, decryptRes.getProcessedBytes(), "Decrypted length must be sliced to exact 24 bytes");
        assertArrayEquals(BOOK_INPUT_24B, decryptRes.getData());
    }

    // =========================================================================
    // 3. CTS MODE & AUTO-IV GENERATION TESTS (Exercise 3.4)
    // =========================================================================

    /**
     * Verifies that Cipher Text Stealing (CTS) mode encrypts 24 bytes into exactly 24 bytes
     * without ciphertext expansion and auto-generates an IV when none is supplied (Exercise 3.4).
     *
     * @throws CryptoOperationException if cipher operation fails unexpectedly
     */
    @Test
    @DisplayName("Exercise 3.4: CTS Mode Preserves Exact 24-Byte Length and Auto-Generates IV")
    void testCtsModePreservesLengthAndAutoGeneratesIv() throws CryptoOperationException
    {
        SymmetricCipherSpec ctsSpec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.CTS)
            .padding(PaddingScheme.CTS)
            .build();

        CryptoRequest encryptReq = CryptoRequest.builder()
            .spec(ctsSpec)
            .key(BOOK_AES_KEY)
            .data(BOOK_INPUT_24B)
            .build();

        CryptoResponse encryptRes = this.cipherService.encrypt(encryptReq);
        assertEquals(24, encryptRes.getProcessedBytes(), "CTS mode must not expand 24-byte payload");
        assertEquals(16, encryptRes.getIv().length, "Auto-generated AES IV must be 16 bytes");

        CryptoRequest decryptReq = CryptoRequest.builder()
            .spec(ctsSpec)
            .key(BOOK_AES_KEY)
            .iv(encryptRes.getIv())
            .data(encryptRes.getData())
            .build();

        CryptoResponse decryptRes = this.cipherService.decrypt(decryptReq);
        assertArrayEquals(BOOK_INPUT_24B, decryptRes.getData());
    }

    // =========================================================================
    // 4. NEGATIVE & SECURITY INVARIANT TESTS (Exercise 3.2b, Bad Keys, Bad Padding)
    // =========================================================================

    /**
     * Verifies Exercise 3.2b: Decrypting CBC ciphertext with an incorrect IV corrupts ONLY the
     * first block (bytes 0..15), while the second block (bytes 16..31) decrypts accurately.
     *
     * @throws CryptoOperationException if cipher operation fails unexpectedly
     */
    @Test
    @DisplayName("Exercise 3.2b: Wrong IV in CBC Mode Corrupts Only First Block")
    void testWrongIvInCbcCorruptsOnlyFirstBlock() throws CryptoOperationException
    {
        SymmetricCipherSpec cbcSpec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.CBC)
            .padding(PaddingScheme.NO_PADDING)
            .build();

        CryptoRequest encryptReq = CryptoRequest.builder()
            .spec(cbcSpec)
            .key(BOOK_AES_KEY)
            .iv(BOOK_AES_IV)
            .data(BOOK_INPUT_32B)
            .build();
        CryptoResponse encryptRes = this.cipherService.encrypt(encryptReq);

        byte[] wrongIv = Hex.decode("ffffffffffffffffffffffffffffffff");
        CryptoRequest decryptWithWrongIv = CryptoRequest.builder()
            .spec(cbcSpec)
            .key(BOOK_AES_KEY)
            .iv(wrongIv)
            .data(encryptRes.getData())
            .build();
        CryptoResponse decryptRes = this.cipherService.decrypt(decryptWithWrongIv);

        byte[] firstBlockExpected = Arrays.copyOfRange(BOOK_INPUT_32B, 0, 16);
        byte[] firstBlockActual   = Arrays.copyOfRange(decryptRes.getData(), 0, 16);
        byte[] secondBlockExpected = Arrays.copyOfRange(BOOK_INPUT_32B, 16, 32);
        byte[] secondBlockActual   = Arrays.copyOfRange(decryptRes.getData(), 16, 32);

        assertFalse(Arrays.equals(firstBlockExpected, firstBlockActual), "First block must be corrupted by wrong IV");
        assertArrayEquals(secondBlockExpected, secondBlockActual, "Second block must still decrypt correctly");
    }

    /**
     * Verifies that an invalid AES key length (e.g., 10 bytes) throws {@link CryptoOperationException}.
     */
    @Test
    @DisplayName("Negative: Invalid AES Key Length Throws CryptoOperationException")
    void testInvalidKeyLengthThrowsException()
    {
        SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.ECB)
            .padding(PaddingScheme.PKCS7)
            .build();

        CryptoRequest invalidKeyReq = CryptoRequest.builder()
            .spec(spec)
            .key(new byte[10])
            .data(BOOK_INPUT_16B)
            .build();

        assertThrows(CryptoOperationException.class, () -> this.cipherService.encrypt(invalidKeyReq));
    }

    /**
     * Verifies that tampered/corrupted ciphertext under PKCS#7 padding throws {@link CryptoOperationException}.
     *
     * @throws CryptoOperationException if encryption setup fails
     */
    @Test
    @DisplayName("Negative: Corrupted Ciphertext With PKCS#7 Throws CryptoOperationException")
    void testCorruptedCiphertextThrowsException() throws CryptoOperationException
    {
        SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.CBC)
            .padding(PaddingScheme.PKCS7)
            .build();

        CryptoRequest encryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(BOOK_AES_KEY)
            .iv(BOOK_AES_IV)
            .data(BOOK_INPUT_24B)
            .build();
        CryptoResponse encryptRes = this.cipherService.encrypt(encryptReq);

        byte[] corrupted = encryptRes.getData();
        corrupted[corrupted.length - 1] ^= 0x55;

        CryptoRequest decryptReq = CryptoRequest.builder()
            .spec(spec)
            .key(BOOK_AES_KEY)
            .iv(BOOK_AES_IV)
            .data(corrupted)
            .build();

        assertThrows(CryptoOperationException.class, () -> this.cipherService.decrypt(decryptReq));
    }

    /**
     * Verifies that CTS mode rejects inputs whose length is less than or equal to a single block.
     */
    @Test
    @DisplayName("Negative: CTS Mode With Single-Block Input Throws CryptoOperationException")
    void testCtsWithSingleBlockThrowsException()
    {
        SymmetricCipherSpec ctsSpec = SymmetricCipherSpec.builder()
            .algorithm(CipherAlgorithm.AES)
            .mode(BlockCipherMode.CTS)
            .padding(PaddingScheme.CTS)
            .build();

        CryptoRequest singleBlockReq = CryptoRequest.builder()
            .spec(ctsSpec)
            .key(BOOK_AES_KEY)
            .iv(BOOK_AES_IV)
            .data(BOOK_INPUT_16B)
            .build();

        assertThrows(CryptoOperationException.class, () -> this.cipherService.encrypt(singleBlockReq));
    }

    /**
     * Verifies that {@link CryptoRequest} and {@link CryptoResponse} protect internal arrays via defensive copies.
     */
    @Test
    @DisplayName("Security Invariant: DTOs Enforce Defensive Copying of Sensitive Byte Arrays")
    void testDtoDefensiveCopying()
    {
        byte[] externalKey = Arrays.copyOf(BOOK_AES_KEY, BOOK_AES_KEY.length);
        SymmetricCipherSpec spec = SymmetricCipherSpec.builder().build();

        CryptoRequest request = CryptoRequest.builder()
            .spec(spec)
            .key(externalKey)
            .data(BOOK_INPUT_16B)
            .build();

        // Mutate external array after building DTO
        Arrays.fill(externalKey, (byte) 0xFF);
        assertArrayEquals(BOOK_AES_KEY, request.getKey(), "Mutating caller array must not affect CryptoRequest");

        // Mutate array returned by getter
        byte[] retrievedKey = request.getKey();
        Arrays.fill(retrievedKey, (byte) 0x00);
        assertArrayEquals(BOOK_AES_KEY, request.getKey(), "Mutating getter return value must not affect CryptoRequest");
        assertNotNull(request.getSpec());
    }
}
