package de.cryptogym.service;

/**
 * Factory Method pattern for creating {@link SymmetricCipherService} instances.
 * <p>
 * Enables seamless substitution of cryptographic service implementations across
 * application layers and unit tests.
 * </p>
 *
 * @author Daniel
 */
public final class CipherServiceFactory
{
    private CipherServiceFactory()
    {
    }

    /**
     * Creates and returns a configured {@link SymmetricCipherService} backed by the Bouncy Castle provider.
     *
     * @return non-null {@link SymmetricCipherService} instance
     */
    public static SymmetricCipherService createSymmetricCipherService()
    {
        return new BouncyCastleCipherService();
    }
}
