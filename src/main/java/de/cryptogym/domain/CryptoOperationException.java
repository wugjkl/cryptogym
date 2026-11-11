package de.cryptogym.domain;

import java.security.GeneralSecurityException;

/**
 * Checked domain exception thrown when a cryptographic operation (encryption, decryption,
 * key generation, or parameter validation) fails.
 * <p>
 * Replaces generic {@code Exception} declarations with a specific, meaningful contract
 * preserving the underlying JCA {@link GeneralSecurityException} cause.
 * </p>
 *
 * @author Daniel
 */
public class CryptoOperationException extends GeneralSecurityException
{
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@code CryptoOperationException} with the specified detail message.
     *
     * @param message human-readable description of the cryptographic failure
     */
    public CryptoOperationException(String message)
    {
        super(message);
    }

    /**
     * Constructs a new {@code CryptoOperationException} with the specified detail message and root cause.
     *
     * @param message human-readable description of the cryptographic failure
     * @param cause   underlying security or parameter exception
     */
    public CryptoOperationException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
