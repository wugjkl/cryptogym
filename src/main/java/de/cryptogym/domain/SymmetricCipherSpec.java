package de.cryptogym.domain;

import java.util.Objects;

/**
 * Immutable Data Transfer Object (DTO) specifying a symmetric cipher configuration
 * (algorithm, mode of operation, and padding scheme).
 * <p>
 * Constructed via the {@link Builder} pattern to enforce invariants and encapsulate
 * provider-specific transformation strings (such as {@code AES/CBC/CTSPadding} for CTS).
 * </p>
 *
 * @author Daniel
 */
public final class SymmetricCipherSpec
{
    private final CipherAlgorithm algorithm;
    private final BlockCipherMode mode;
    private final PaddingScheme padding;

    private SymmetricCipherSpec(Builder builder)
    {
        this.algorithm = Objects.requireNonNull(builder.algorithm, "CipherAlgorithm must not be null");
        this.mode = Objects.requireNonNull(builder.mode, "BlockCipherMode must not be null");
        this.padding = Objects.requireNonNull(builder.padding, "PaddingScheme must not be null");
    }

    /**
     * Returns the configured symmetric cipher algorithm.
     *
     * @return non-null {@link CipherAlgorithm}
     */
    public CipherAlgorithm getAlgorithm()
    {
        return this.algorithm;
    }

    /**
     * Returns the configured block cipher mode of operation.
     *
     * @return non-null {@link BlockCipherMode}
     */
    public BlockCipherMode getMode()
    {
        return this.mode;
    }

    /**
     * Returns the configured padding scheme.
     *
     * @return non-null {@link PaddingScheme}
     */
    public PaddingScheme getPadding()
    {
        return this.padding;
    }

    /**
     * Resolves the canonical JCA transformation string of the form {@code Algorithm/Mode/Padding}.
     * For {@link BlockCipherMode#CTS}, returns {@code Algorithm/CBC/CTSPadding} as required by
     * the Bouncy Castle provider specification.
     *
     * @return non-null JCA transformation string
     */
    public String toJcaTransformation()
    {
        if (this.mode == BlockCipherMode.CTS)
        {
            return this.algorithm.getJcaName() + "/CBC/" + PaddingScheme.CTS.getJcaName();
        }
        return this.algorithm.getJcaName() + "/" + this.mode.getJcaName() + "/" + this.padding.getJcaName();
    }

    /**
     * Creates a new {@link Builder} instance initialized with default AES/CBC/PKCS7 settings.
     *
     * @return a new {@link Builder}
     */
    public static Builder builder()
    {
        return new Builder();
    }

    /**
     * Builder for constructing immutable {@link SymmetricCipherSpec} instances.
     *
     * @author Daniel
     */
    public static final class Builder
    {
        private CipherAlgorithm algorithm = CipherAlgorithm.AES;
        private BlockCipherMode mode = BlockCipherMode.CBC;
        private PaddingScheme padding = PaddingScheme.PKCS7;

        /**
         * Sets the symmetric block cipher algorithm.
         *
         * @param algorithm target {@link CipherAlgorithm}; must not be null
         * @return this builder instance
         */
        public Builder algorithm(CipherAlgorithm algorithm)
        {
            this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
            return this;
        }

        /**
         * Sets the block cipher mode of operation.
         *
         * @param mode target {@link BlockCipherMode}; must not be null
         * @return this builder instance
         */
        public Builder mode(BlockCipherMode mode)
        {
            this.mode = Objects.requireNonNull(mode, "mode must not be null");
            return this;
        }

        /**
         * Sets the padding scheme.
         *
         * @param padding target {@link PaddingScheme}; must not be null
         * @return this builder instance
         */
        public Builder padding(PaddingScheme padding)
        {
            this.padding = Objects.requireNonNull(padding, "padding must not be null");
            return this;
        }

        /**
         * Builds the immutable {@link SymmetricCipherSpec}.
         *
         * @return configured {@link SymmetricCipherSpec}
         */
        public SymmetricCipherSpec build()
        {
            return new SymmetricCipherSpec(this);
        }
    }
}
