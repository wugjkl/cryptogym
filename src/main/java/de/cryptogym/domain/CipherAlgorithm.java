package de.cryptogym.domain;

/**
 * Supported symmetric block cipher algorithms and their intrinsic block sizes.
 *
 * @author Daniel
 */
public enum CipherAlgorithm
{
    /**
     * Advanced Encryption Standard (128-bit / 16-byte block size).
     */
    AES("AES", 16),

    /**
     * Data Encryption Standard (64-bit / 8-byte block size).
     */
    DES("DES", 8),

    /**
     * Blowfish symmetric block cipher (64-bit / 8-byte block size).
     */
    BLOWFISH("Blowfish", 8);

    private final String jcaName;
    private final int blockSizeBytes;

    CipherAlgorithm(String jcaName, int blockSizeBytes)
    {
        this.jcaName = jcaName;
        this.blockSizeBytes = blockSizeBytes;
    }

    /**
     * Returns the canonical JCA algorithm name recognized by cryptographic providers.
     *
     * @return non-null JCA algorithm identifier (e.g., {@code "AES"} or {@code "DES"})
     */
    public String getJcaName()
    {
        return this.jcaName;
    }

    /**
     * Returns the fixed cipher block size in bytes.
     *
     * @return positive block length in bytes (e.g., 16 for AES, 8 for DES)
     */
    public int getBlockSizeBytes()
    {
        return this.blockSizeBytes;
    }
}
