package de.cryptogym.domain;

/**
 * Supported block cipher modes of operation.
 *
 * @author Daniel
 */
public enum BlockCipherMode
{
    /**
     * Electronic Codebook mode. Encrypts each block independently without an IV.
     */
    ECB("ECB", false),

    /**
     * Cipher Block Chaining mode. Chains blocks via XOR and requires an IV.
     */
    CBC("CBC", true),

    /**
     * Cipher Text Stealing mode over CBC. Eliminates padding expansion for inputs exceeding one block.
     */
    CTS("CTS", true);

    private final String jcaName;
    private final boolean requiresIv;

    BlockCipherMode(String jcaName, boolean requiresIv)
    {
        this.jcaName = jcaName;
        this.requiresIv = requiresIv;
    }

    /**
     * Returns the mode identifier used in JCA transformations.
     *
     * @return non-null mode name
     */
    public String getJcaName()
    {
        return this.jcaName;
    }

    /**
     * Indicates whether this mode of operation requires an Initialization Vector (IV).
     *
     * @return {@code true} if an IV is required (e.g., CBC, CTS); {@code false} otherwise (e.g., ECB)
     */
    public boolean requiresIv()
    {
        return this.requiresIv;
    }
}
