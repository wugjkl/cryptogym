package de.cryptogym.domain;

/**
 * Supported block cipher padding schemes as specified in Hook &amp; Eaves (2025, pp. 29-33).
 *
 * @author Daniel
 */
public enum PaddingScheme
{
    /**
     * No padding applied. Input length must be an exact multiple of the cipher block size.
     */
    NO_PADDING("NoPadding"),

    /**
     * PKCS#7 padding (and PKCS#5 synonym in JCA). Pads with byte values equal to the pad length.
     */
    PKCS7("PKCS7Padding"),

    /**
     * PKCS#5 padding identifier for 8-byte and general block ciphers in JCA.
     */
    PKCS5("PKCS5Padding"),

    /**
     * ISO 7816-4 padding. First pad byte is {@code 0x80}, followed by {@code 0x00} bytes.
     */
    ISO7816_4("ISO7816-4Padding"),

    /**
     * ISO 10126-2 padding. Random pad bytes followed by the pad byte count in the final byte.
     */
    ISO10126_2("ISO10126-2Padding"),

    /**
     * Trailing Bit Complement (TBC) padding. Pads with the complement of the last bit of plaintext.
     */
    TBC("TBCPadding"),

    /**
     * ANSI X9.23 padding. Zero (or random) bytes followed by the pad byte count in the final byte.
     */
    X9_23("X9.23Padding"),

    /**
     * Zero-byte padding. Pads incomplete blocks with {@code 0x00}; unsuitable for data ending in zero.
     */
    ZERO_BYTE("ZeroBytePadding"),

    /**
     * Cipher Text Stealing mechanism represented as a padding transformation in Bouncy Castle.
     */
    CTS("CTSPadding");

    private final String jcaName;

    PaddingScheme(String jcaName)
    {
        this.jcaName = jcaName;
    }

    /**
     * Returns the JCA transformation padding name expected by Bouncy Castle.
     *
     * @return non-null JCA padding string (e.g., {@code "PKCS7Padding"}, {@code "ISO7816-4Padding"})
     */
    public String getJcaName()
    {
        return this.jcaName;
    }
}
