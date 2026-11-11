package de.cryptogym.service;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import de.cryptogym.domain.BlockCipherMode;
import de.cryptogym.domain.CipherAlgorithm;
import de.cryptogym.domain.CryptoOperationException;
import de.cryptogym.domain.CryptoRequest;
import de.cryptogym.domain.CryptoResponse;
import de.cryptogym.domain.SymmetricCipherSpec;

/**
 * Bouncy Castle implementation of {@link SymmetricCipherService} supporting ECB, CBC, and CTS
 * modes along with all standard block cipher padding schemes from Hook &amp; Eaves (2025, Chapters 1-2).
 *
 * @author Daniel
 */
public class BouncyCastleCipherService implements SymmetricCipherService
{
    /**
     * Constructs a new {@code BouncyCastleCipherService} and ensures the {@code "BC"} provider is registered.
     */
    public BouncyCastleCipherService()
    {
        BouncyCastleProviderRegistrar.getInstance().ensureRegistered();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CryptoResponse encrypt(CryptoRequest request) throws CryptoOperationException
    {
        Objects.requireNonNull(request, "CryptoRequest must not be null");
        SymmetricCipherSpec spec = request.getSpec();
        byte[] keyBytes = request.getKey();
        byte[] input = request.getData();

        validateKeyNonEmpty(keyBytes);
        validateCtsInputLength(spec, input);

        try
        {
            SecretKeySpec key = new SecretKeySpec(keyBytes, spec.getAlgorithm().getJcaName());
            Cipher cipher = Cipher.getInstance(
                spec.toJcaTransformation(),
                BouncyCastleProviderRegistrar.PROVIDER_NAME
            );

            byte[] effectiveIv = new byte[0];
            if (spec.getMode().requiresIv())
            {
                if (request.hasIv())
                {
                    effectiveIv = request.getIv();
                    validateIvLength(spec.getAlgorithm(), effectiveIv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(effectiveIv));
                }
                else
                {
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    byte[] generatedIv = cipher.getIV();
                    effectiveIv = (generatedIv != null) ? generatedIv : new byte[0];
                }
            }
            else
            {
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }

            byte[] finalOutput = new byte[cipher.getOutputSize(input.length)];
            int len = cipher.update(input, 0, input.length, finalOutput, 0);
            len += cipher.doFinal(finalOutput, len);

            byte[] actualCiphertext = Arrays.copyOfRange(finalOutput, 0, len);
            return CryptoResponse.builder()
                .data(actualCiphertext)
                .iv(effectiveIv)
                .processedBytes(len)
                .build();
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            throw new CryptoOperationException(
                "Encryption failed for " + spec.toJcaTransformation() + ": " + e.getMessage(),
                e
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CryptoResponse decrypt(CryptoRequest request) throws CryptoOperationException
    {
        Objects.requireNonNull(request, "CryptoRequest must not be null");
        SymmetricCipherSpec spec = request.getSpec();
        byte[] keyBytes = request.getKey();
        byte[] ciphertext = request.getData();

        validateKeyNonEmpty(keyBytes);
        validateCtsInputLength(spec, ciphertext);

        try
        {
            SecretKeySpec key = new SecretKeySpec(keyBytes, spec.getAlgorithm().getJcaName());
            Cipher cipher = Cipher.getInstance(
                spec.toJcaTransformation(),
                BouncyCastleProviderRegistrar.PROVIDER_NAME
            );

            byte[] effectiveIv = new byte[0];
            if (spec.getMode().requiresIv())
            {
                if (!request.hasIv())
                {
                    throw new CryptoOperationException(
                        "Initialization Vector (IV) is required for decryption in " + spec.getMode() + " mode"
                    );
                }
                effectiveIv = request.getIv();
                validateIvLength(spec.getAlgorithm(), effectiveIv);
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(effectiveIv));
            }
            else
            {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }

            byte[] finalOutput = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.update(ciphertext, 0, ciphertext.length, finalOutput, 0);
            len += cipher.doFinal(finalOutput, len);

            byte[] actualPlaintext = Arrays.copyOfRange(finalOutput, 0, len);
            return CryptoResponse.builder()
                .data(actualPlaintext)
                .iv(effectiveIv)
                .processedBytes(len)
                .build();
        }
        catch (CryptoOperationException e)
        {
            throw e;
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            throw new CryptoOperationException(
                "Decryption failed for " + spec.toJcaTransformation() + ": " + e.getMessage(),
                e
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecretKey generateKey(CipherAlgorithm algorithm, int keyBitSize) throws CryptoOperationException
    {
        Objects.requireNonNull(algorithm, "CipherAlgorithm must not be null");
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance(
                algorithm.getJcaName(),
                BouncyCastleProviderRegistrar.PROVIDER_NAME
            );
            keyGen.init(keyBitSize);
            return keyGen.generateKey();
        }
        catch (GeneralSecurityException | IllegalArgumentException e)
        {
            throw new CryptoOperationException(
                "Key generation failed for " + algorithm.getJcaName() + " (" + keyBitSize + " bits): " + e.getMessage(),
                e
            );
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] generateIv(CipherAlgorithm algorithm) throws CryptoOperationException
    {
        Objects.requireNonNull(algorithm, "CipherAlgorithm must not be null");
        try
        {
            Cipher cipher = Cipher.getInstance(
                algorithm.getJcaName() + "/CBC/NoPadding",
                BouncyCastleProviderRegistrar.PROVIDER_NAME
            );
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            random.nextBytes(iv);
            return iv;
        }
        catch (GeneralSecurityException e)
        {
            throw new CryptoOperationException(
                "IV generation failed for " + algorithm.getJcaName() + ": " + e.getMessage(),
                e
            );
        }
    }

    private void validateKeyNonEmpty(byte[] keyBytes) throws CryptoOperationException
    {
        if (keyBytes == null || keyBytes.length == 0)
        {
            throw new CryptoOperationException("Secret key must not be empty");
        }
    }

    private void validateIvLength(CipherAlgorithm algorithm, byte[] iv) throws CryptoOperationException
    {
        int expected = algorithm.getBlockSizeBytes();
        if (iv.length != expected)
        {
            throw new CryptoOperationException(
                "Invalid IV length for " + algorithm.getJcaName()
                + ": expected " + expected + " bytes, but got " + iv.length + " bytes"
            );
        }
    }

    private void validateCtsInputLength(SymmetricCipherSpec spec, byte[] input) throws CryptoOperationException
    {
        if (spec.getMode() == BlockCipherMode.CTS)
        {
            int blockSize = spec.getAlgorithm().getBlockSizeBytes();
            if (input == null || input.length <= blockSize)
            {
                throw new CryptoOperationException(
                    "CTS mode requires input strictly greater than one cipher block (> " + blockSize + " bytes)"
                );
            }
        }
    }
}
