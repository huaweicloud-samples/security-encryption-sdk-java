package com.huaweicloud.encryptionsdk.common;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.Provider;
import java.security.Security;

/**
 * Crypto provider manager, responsible for selecting and caching the appropriate JCA provider.
 *
 * <p>Provider selection order:
 * <ol>
 *   <li>If JVM property {@code crypto.sdk.disableKae=true}, use SunJCE directly</li>
 *   <li>If KAE provider is already registered in JCA, use it</li>
 *   <li>Try to create KAE provider via reflection, use it if available</li>
 *   <li>Fall back to SunJCE provider (supports AES-NI hardware acceleration)</li>
 * </ol>
 *
 * <p>SM algorithms (SM2/SM3/SM4) always use BouncyCastle via {@link #getBcProvider()}.
 *
 * <p>This class is thread-safe. Provider instances are lazily initialized using
 * double-checked locking with volatile fields.
 */
public final class ProviderManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProviderManager.class);

    private static final String KAE_PROVIDER_CLASS =
            "org.openeuler.security.openssl.KAEProvider";

    private static final String KAE_PROVIDER_NAME =
            "KAEProvider";

    private static final String DISABLE_KAE_PROPERTY =
            "crypto.sdk.disableKae";

    private static volatile Provider provider;

    private static volatile Provider bcProvider;

    private static volatile Provider sunJceProvider;

    private ProviderManager() {
    }

    /**
     * Returns the selected crypto provider, initializing it on first call.
     * Thread-safe via double-checked locking.
     *
     * @return the active crypto provider (KAE or SunJCE)
     */
    public static Provider getProvider() {
        if (provider == null) {
            synchronized (ProviderManager.class) {
                if (provider == null) {
                    provider = initProvider();
                }
            }
        }
        return provider;
    }

    /**
     * Returns the BouncyCastle provider instance, creating it on first call.
     * Used for SM algorithms (SM2/SM3/SM4).
     * Thread-safe via double-checked locking.
     *
     * @return the BouncyCastle provider
     */
    public static Provider getBcProvider() {
        if (bcProvider == null) {
            synchronized (ProviderManager.class) {
                if (bcProvider == null) {
                    bcProvider = new BouncyCastleProvider();
                }
            }
        }
        return bcProvider;
    }

    /**
     * Returns the SunJCE provider instance, creating it on first call.
     * SunJCE is the JDK built-in provider that supports AES-NI hardware acceleration,
     * offering significantly better performance than BouncyCastle for AES algorithms.
     * Thread-safe via double-checked locking.
     *
     * @return the SunJCE provider
     */
    public static Provider getSunJceProvider() {
        if (sunJceProvider == null) {
            synchronized (ProviderManager.class) {
                if (sunJceProvider == null) {
                    Provider jce = Security.getProvider("SunJCE");
                    if (jce == null) {
                        LOGGER.error("SunJCE provider not available, falling back to BouncyCastle");
                        return getBcProvider();
                    }
                    sunJceProvider = jce;
                }
            }
        }
        return sunJceProvider;
    }

    private static Provider initProvider() {
        if (isKaeDisabled()) {
            LOGGER.info("KAE is disabled by JVM property, using SunJCE provider");
            return getSunJceProvider();
        }

        Provider registeredKae = Security.getProvider("KAEProvider");
        if (isProviderAvailable(registeredKae)) {
            LOGGER.info("Crypto provider selected: {}", registeredKae.getName());
            return registeredKae;
        }

        Provider kaeProvider = createKaeProvider();
        if (isProviderAvailable(kaeProvider)) {
            LOGGER.info("Crypto provider selected: {}", kaeProvider.getName());
            return kaeProvider;
        }

        LOGGER.info("KAE provider not available, falling back to SunJCE provider");
        return getSunJceProvider();
    }

    private static boolean isProviderAvailable(Provider provider) {
        if (provider == null) {
            return false;
        }
        try {
            Cipher.getInstance("AES/GCM/NoPadding", provider);
            return true;
        } catch (Exception e) {
            LOGGER.debug("Provider {} not available for AES/GCM: {}", provider.getName(), e.getMessage());
            return false;
        }
    }

    private static Provider createKaeProvider() {
        try {
            Class<?> clazz = Class.forName(KAE_PROVIDER_CLASS);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            return (Provider) instance;
        } catch (Exception e) {
            LOGGER.warn("Failed to create KAE provider by reflection: {}", e.getMessage());
            return null;
        }
    }

    private static boolean isKaeDisabled() {
        return Boolean.parseBoolean(
                System.getProperty(DISABLE_KAE_PROPERTY, "false"));
    }

    /**
     * Checks whether the currently active provider is KAE.
     *
     * @return true if KAE provider is in use
     */
    public static boolean isKaeEnabled() {
        Provider currentProvider = getProvider();
        return currentProvider != null && KAE_PROVIDER_NAME.equals(currentProvider.getName());
    }

    /**
     * Returns the name of the currently active provider.
     *
     * @return provider name, or "UNKNOWN" if no provider is available
     */
    public static String currentProvider() {
        Provider currentProvider = getProvider();
        return currentProvider == null ? "UNKNOWN" : currentProvider.getName();
    }
}
