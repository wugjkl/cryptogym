package de.cryptogym.controller;

import java.util.Objects;
import javax.crypto.SecretKey;
import de.cryptogym.domain.CipherAlgorithm;
import de.cryptogym.domain.CryptoOperationException;
import de.cryptogym.domain.CryptoRequest;
import de.cryptogym.domain.CryptoResponse;
import de.cryptogym.domain.SymmetricCipherSpec;
import de.cryptogym.model.CryptoGymModel;
import de.cryptogym.service.CipherServiceFactory;
import de.cryptogym.service.SymmetricCipherService;

/**
 * Controller in the MVC architecture coordinating user actions between the {@link CryptoGymModel}
 * and the {@link SymmetricCipherService}.
 * <p>
 * Translates UI/model state into immutable {@link CryptoRequest} DTOs via the Builder pattern
 * and updates the model with the resulting {@link CryptoResponse} or error status.
 * </p>
 *
 * @author Daniel
 */
public class CryptoGymController
{
    private final CryptoGymModel model;
    private final SymmetricCipherService cipherService;

    /**
     * Constructs a controller with a default {@link CryptoGymModel} and Bouncy Castle service.
     */
    public CryptoGymController()
    {
        this(new CryptoGymModel(), CipherServiceFactory.createSymmetricCipherService());
    }

    /**
     * Constructs a controller with the specified model and cipher service (enabling dependency injection).
     *
     * @param model         non-null {@link CryptoGymModel}
     * @param cipherService non-null {@link SymmetricCipherService}
     */
    public CryptoGymController(CryptoGymModel model, SymmetricCipherService cipherService)
    {
        this.model = Objects.requireNonNull(model, "model must not be null");
        this.cipherService = Objects.requireNonNull(cipherService, "cipherService must not be null");
    }

    /**
     * Returns the underlying application state model.
     *
     * @return non-null {@link CryptoGymModel}
     */
    public CryptoGymModel getModel()
    {
        return this.model;
    }

    /**
     * Executes encryption using the current configuration, key, optional IV, and plaintext in the model.
     * Updates the ciphertext, effective IV, and status message in the model.
     */
    public void onEncrypt()
    {
        try
        {
            SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
                .algorithm(this.model.getAlgorithm())
                .mode(this.model.getMode())
                .padding(this.model.getPadding())
                .build();

            CryptoRequest request = CryptoRequest.builder()
                .spec(spec)
                .key(this.model.getKeyBytes())
                .iv(this.model.getIvBytes())
                .data(this.model.getPlaintextBytes())
                .build();

            CryptoResponse response = this.cipherService.encrypt(request);
            this.model.setCiphertextBytes(response.getData());
            if (spec.getMode().requiresIv())
            {
                this.model.setIvBytes(response.getIv());
            }
            this.model.setStatus(
                "Encryption successful (" + spec.toJcaTransformation()
                + ", " + response.getProcessedBytes() + " bytes)"
            );
        }
        catch (CryptoOperationException | IllegalArgumentException e)
        {
            this.model.setStatus("Encryption error: " + e.getMessage());
        }
    }

    /**
     * Executes decryption using the current configuration, key, IV, and ciphertext in the model.
     * Updates the plaintext and status message in the model.
     */
    public void onDecrypt()
    {
        try
        {
            SymmetricCipherSpec spec = SymmetricCipherSpec.builder()
                .algorithm(this.model.getAlgorithm())
                .mode(this.model.getMode())
                .padding(this.model.getPadding())
                .build();

            CryptoRequest request = CryptoRequest.builder()
                .spec(spec)
                .key(this.model.getKeyBytes())
                .iv(this.model.getIvBytes())
                .data(this.model.getCiphertextBytes())
                .build();

            CryptoResponse response = this.cipherService.decrypt(request);
            this.model.setPlaintextBytes(response.getData());
            this.model.setStatus(
                "Decryption successful (" + spec.toJcaTransformation()
                + ", " + response.getProcessedBytes() + " bytes)"
            );
        }
        catch (CryptoOperationException | IllegalArgumentException e)
        {
            this.model.setStatus("Decryption error: " + e.getMessage());
        }
    }

    /**
     * Generates a new random secret key of the specified bit length for the active algorithm
     * and stores it in the model.
     *
     * @param keyBitSize key size in bits (e.g., 128 for AES, 64 for DES)
     */
    public void onGenerateKey(int keyBitSize)
    {
        try
        {
            CipherAlgorithm algorithm = this.model.getAlgorithm();
            SecretKey secretKey = this.cipherService.generateKey(algorithm, keyBitSize);
            this.model.setKeyBytes(secretKey.getEncoded());
            this.model.setStatus("Generated " + keyBitSize + "-bit key for " + algorithm.getJcaName());
        }
        catch (CryptoOperationException e)
        {
            this.model.setStatus("Key generation error: " + e.getMessage());
        }
    }

    /**
     * Generates a new random Initialization Vector (IV) matching the active algorithm's block size
     * and stores it in the model.
     */
    public void onGenerateIv()
    {
        try
        {
            CipherAlgorithm algorithm = this.model.getAlgorithm();
            byte[] iv = this.cipherService.generateIv(algorithm);
            this.model.setIvBytes(iv);
            this.model.setStatus("Generated " + iv.length + "-byte IV for " + algorithm.getJcaName());
        }
        catch (CryptoOperationException e)
        {
            this.model.setStatus("IV generation error: " + e.getMessage());
        }
    }

    /**
     * Resets all fields in the model to their initial state.
     */
    public void onReset()
    {
        this.model.reset();
    }
}
