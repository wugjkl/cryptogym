package de.cryptogym.domain;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable Data Transfer Object (DTO) representing the result of a symmetric
 * encryption or decryption operation.
 * <p>
 * Encapsulates the resulting output bytes, the Initialization Vector (IV) used or
 * generated during the operation, and the exact number of processed output bytes.
 * </p>
 *
 * @author Daniel
 */
public final class CryptoResponse
{
    private final byte[] data;
    private final byte[] iv;
    private final int processedBytes;

    private CryptoResponse(Builder builder)
    {
        Objects.requireNonNull(builder.data, "Output data must not be null");
        this.data = Arrays.copyOf(builder.data, builder.data.length);
        this.iv = (builder.iv != null) ? Arrays.copyOf(builder.iv, builder.iv.length) : new byte[0];
        this.processedBytes = builder.processedBytes;
    }

    /**
     * Returns a defensive copy of the resulting output bytes (ciphertext or decrypted plaintext).
     *
     * @return non-null copy of the output bytes
     */
    public byte[] getData()
    {
        return Arrays.copyOf(this.data, this.data.length);
    }

    /**
     * Returns a defensive copy of the Initialization Vector (IV) used in the operation,
     * or an empty byte array if the mode does not use an IV.
     *
     * @return non-null copy of the IV bytes
     */
    public byte[] getIv()
    {
        return Arrays.copyOf(this.iv, this.iv.length);
    }

    /**
     * Returns the exact number of valid output bytes produced by the cipher operation.
     *
     * @return non-negative byte count
     */
    public int getProcessedBytes()
    {
        return this.processedBytes;
    }

    /**
     * Creates a new {@link Builder} for constructing a {@link CryptoResponse}.
     *
     * @return new {@link Builder} instance
     */
    public static Builder builder()
    {
        return new Builder();
    }

    /**
     * Builder for constructing immutable {@link CryptoResponse} DTOs.
     *
     * @author Daniel
     */
    public static final class Builder
    {
        private byte[] data = new byte[0];
        private byte[] iv = new byte[0];
        private int processedBytes = 0;

        /**
         * Sets the output data bytes (defensively copied).
         *
         * @param data non-null output byte array
         * @return this builder instance
         */
        public Builder data(byte[] data)
        {
            Objects.requireNonNull(data, "data must not be null");
            this.data = Arrays.copyOf(data, data.length);
            this.processedBytes = data.length;
            return this;
        }

        /**
         * Sets the Initialization Vector (IV) bytes used or generated (defensively copied).
         *
         * @param iv IV byte array, or {@code null} if not applicable
         * @return this builder instance
         */
        public Builder iv(byte[] iv)
        {
            this.iv = (iv != null) ? Arrays.copyOf(iv, iv.length) : new byte[0];
            return this;
        }

        /**
         * Sets the exact number of processed output bytes.
         *
         * @param processedBytes non-negative number of bytes
         * @return this builder instance
         */
        public Builder processedBytes(int processedBytes)
        {
            this.processedBytes = processedBytes;
            return this;
        }

        /**
         * Builds the immutable {@link CryptoResponse}.
         *
         * @return configured {@link CryptoResponse}
         */
        public CryptoResponse build()
        {
            return new CryptoResponse(this);
        }
    }
}
