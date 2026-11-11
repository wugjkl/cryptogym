package de.cryptogym.service;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Thread-safe Singleton responsible for registering and verifying the Bouncy Castle
 * JCA/JCE cryptographic provider ({@code "BC"}) within the active JVM runtime.
 *
 * @author Daniel
 */
public final class BouncyCastleProviderRegistrar
{
    /**
     * Canonical JCA provider name for Bouncy Castle.
     */
    public static final String PROVIDER_NAME = "BC";

    private static final BouncyCastleProviderRegistrar INSTANCE = new BouncyCastleProviderRegistrar();

    private BouncyCastleProviderRegistrar()
    {
        ensureRegistered();
    }

    /**
     * Returns the singleton registrar instance, ensuring Bouncy Castle is registered.
     *
     * @return non-null {@link BouncyCastleProviderRegistrar} singleton
     */
    public static BouncyCastleProviderRegistrar getInstance()
    {
        return INSTANCE;
    }

    /**
     * Ensures that the {@link BouncyCastleProvider} is registered in {@link Security}.
     * Idempotent: if the provider is already installed, no duplicate registration occurs.
     *
     * @return the registered {@link Provider} instance
     */
    public synchronized Provider ensureRegistered()
    {
        Provider existing = Security.getProvider(PROVIDER_NAME);
        if (existing == null)
        {
            Provider bc = new BouncyCastleProvider();
            Security.addProvider(bc);
            return bc;
        }
        return existing;
    }
}
