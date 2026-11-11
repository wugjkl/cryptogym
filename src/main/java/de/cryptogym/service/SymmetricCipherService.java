package de.cryptogym.service;

import javax.crypto.SecretKey;
import de.cryptogym.domain.CipherAlgorithm;
import de.cryptogym.domain.CryptoOperationException;
import de.cryptogym.domain.CryptoRequest;
import de.cryptogym.domain.CryptoResponse;

/**
 * Service interface defining the contract for symmetric block cipher operations.
 * <p>
 * Decouples client layers (controllers, UI, and tests) from specific JCA provider
 * implementations and operates strictly on raw byte arrays and JCA key abstractions.
 * </p>
 *
 * @author Daniel
 */
public interface SymmetricCipherService
{
    /**
     * Encrypts the plaintext payload specified in the given {@link CryptoRequest}.
     * <p>
     * Preconditions:
     * <ul>
     *   <li>{@code request} must not be {@code null}.</li>
     *   <li>{@code request.getKey()} must match a valid key size for the target algorithm.</li>
     *   <li>If the selected mode requires an IV and {@code request.hasIv()} is {@code false},
     *       a cryptographically random IV of one cipher block size is automatically generated
     *       and returned in {@link CryptoResponse#getIv()}.</li>
     *   <li>For {@code CTS} mode, the input payload length must be strictly greater than one block.</li>
     * </ul>
     *
     * @param request immutable encryption request containing cipher specification, key, optional IV, and plaintext
     * @return immutable {@link CryptoResponse} containing the ciphertext bytes, effective IV, and processed byte count
     * @throws CryptoOperationException if the key size, IV length, block alignment, or cipher configuration is invalid
     */
    CryptoResponse encrypt(CryptoRequest request) throws CryptoOperationException;

    /**
     * Decrypts the ciphertext payload specified in the given {@link CryptoRequest} and removes
     * any configured padding bytes.
     * <p>
     * Preconditions:
     * <ul>
     *   <li>{@code request} must not be {@code null}.</li>
     *   <li>If the selected mode requires an IV (e.g., {@code CBC} or {@code CTS}),
     *       {@code request.getIv()} must be provided and match the cipher's block size.</li>
     * </ul>
     * Postconditions:
     * <ul>
     *   <li>The returned {@link CryptoResponse#getData()} is sliced to the exact unpadded plaintext length
     *       without trailing buffer zero bytes.</li>
     * </ul>
     *
     * @param request immutable decryption request containing cipher specification, key, IV, and ciphertext
     * @return immutable {@link CryptoResponse} containing the exact decrypted plaintext bytes
     * @throws CryptoOperationException if the key, IV, ciphertext length, or padding structure is invalid
     */
    CryptoResponse decrypt(CryptoRequest request) throws CryptoOperationException;

    /**
     * Generates a new cryptographically random secret key for the specified algorithm.
     *
     * @param algorithm  target symmetric cipher algorithm; must not be {@code null}
     * @param keyBitSize key size in bits (e.g., 128, 192, or 256 for AES; 64 for DES)
     * @return newly generated {@link SecretKey}
     * @throws CryptoOperationException if the algorithm is unsupported or the key size is invalid
     */
    SecretKey generateKey(CipherAlgorithm algorithm, int keyBitSize) throws CryptoOperationException;

    /**
     * Generates a cryptographically random Initialization Vector (IV) matching the block size
     * of the specified algorithm.
     *
     * @param algorithm target symmetric cipher algorithm; must not be {@code null}
     * @return newly generated random byte array of length {@code algorithm.getBlockSizeBytes()}
     * @throws CryptoOperationException if the cipher block size cannot be determined
     */
    byte[] generateIv(CipherAlgorithm algorithm) throws CryptoOperationException;
}
