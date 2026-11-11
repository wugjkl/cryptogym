package de.cryptogym.domain;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable Data Transfer Object (DTO) encapsulating all input parameters for a
 * symmetric encryption or decryption operation.
 * <p>
 * Protects sensitive internal state (keys, IVs, and payload bytes) against unintended
 * external modification by performing defensive array copies on construction and retrieval.
 * </p>
 *
 * @author Daniel
 */
public final class CryptoRequest
{
    private final SymmetricCipherSpec spec;
    private final byte[] key;
    private final byte[] iv;
    private final byte[] data;

    private CryptoRequest(Builder builder)
    {
        this.spec = Objects.requireNonNull(builder.spec, "SymmetricCipherSpec must not be null");
        Objects.requireNonNull(builder.key, "Key byte array must not be null");
        Objects.requireNonNull(builder.data, "Input data byte array must not be null");

        this.key = Arrays.copyOf(builder.key, builder.key.length);
        this.data = Arrays.copyOf(builder.data, builder.data.length);
        this.iv = (builder.iv != null) ? Arrays.copyOf(builder.iv, builder.iv.length) : new byte[0];
    }

    /**
     * Returns the cipher specification (algorithm, mode, padding).
     *
     * @return non-null {@link SymmetricCipherSpec}
     */
    public SymmetricCipherSpec getSpec()
    {
        return this.spec;
    }

    /**
     * Returns a defensive copy of the raw secret key bytes.
     *
     * @return non-null copy of the secret key bytes
     */
    public byte[] getKey()
    {
        return Arrays.copyOf(this.key, this.key.length);
    }

    /**
     * Returns a defensive copy of the initialization vector (IV) bytes, or an empty array if none was supplied.
     *
     * @return non-null copy of the IV bytes
     */
    public byte[] getIv()
    {
        return Arrays.copyOf(this.iv, this.iv.length);
    }

    /**
     * Indicates whether a non-empty Initialization Vector (IV) was explicitly provided in this request.
     *
     * @return {@code true} if {@code iv.length > 0}; {@code false} otherwise
     */
    public boolean hasIv()
    {
        return this.iv.length > 0;
    }

    /**
     * Returns a defensive copy of the input payload bytes (plaintext for encryption, ciphertext for decryption).
     *
     * @return non-null copy of the input data bytes
     */
    public byte[] getData()
    {
        return Arrays.copyOf(this.data, this.data.length);
    }

    /**
     * Creates a new {@link Builder} for constructing a {@link CryptoRequest}.
     *
     * @return new {@link Builder} instance
     */
    public static Builder builder()
    {
        return new Builder();
    }

    /**
     * Builder for constructing immutable {@link CryptoRequest} DTOs.
     *
     * @author Daniel
     */
    public static final class Builder
    {
        private SymmetricCipherSpec spec;
        private byte[] key;
        private byte[] iv;
        private byte[] data;

        /**
         * Sets the cipher specification.
         *
         * @param spec non-null {@link SymmetricCipherSpec}
         * @return this builder instance
         */
        public Builder spec(SymmetricCipherSpec spec)
        {
            this.spec = Objects.requireNonNull(spec, "spec must not be null");
            return this;
        }

        /**
         * Sets the secret key bytes (defensively copied).
         *
         * @param key non-null secret key byte array
         * @return this builder instance
         */
        public Builder key(byte[] key)
        {
            Objects.requireNonNull(key, "key must not be null");
            this.key = Arrays.copyOf(key, key.length);
            return this;
        }

        /**
         * Sets the optional initialization vector (IV) bytes (defensively copied).
         *
         * @param iv IV byte array, or {@code null} / empty array to request auto-generation during encryption
         * @return this builder instance
         */
        public Builder iv(byte[] iv)
        {
            this.iv = (iv != null) ? Arrays.copyOf(iv, iv.length) : new byte[0];
            return this;
        }

        /**
         * Sets the input payload bytes (plaintext or ciphertext, defensively copied).
         *
         * @param data non-null payload byte array
         * @return this builder instance
         */
        public Builder data(byte[] data)
        {
            Objects.requireNonNull(data, "data must not be null");
            this.data = Arrays.copyOf(data, data.length);
            return this;
        }

        /**
         * Builds the immutable {@link CryptoRequest} instance.
         *
         * @return validated {@link CryptoRequest}
         */
        public CryptoRequest build()
        {
            return new CryptoRequest(this);
        }
    }
}
