package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.ProviderManager;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ProviderManagerTest {

    @Test
    public void testGetProvider() {
        Provider provider = ProviderManager.getProvider();
        assertNotNull(provider);
        assertTrue(provider.getName().equals("BC") || provider.getName().equals("KAEProvider"));
    }

    @Test
    public void testGetBcProvider() {
        Provider bc = ProviderManager.getBcProvider();
        assertNotNull(bc);
        assertEquals("BC", bc.getName());
    }

    @Test
    public void testCurrentProvider() {
        String name = ProviderManager.currentProvider();
        assertNotNull(name);
        assertTrue(name.equals("BC") || name.equals("KAEProvider"));
    }

    @Test
    public void testIsKaeEnabled() {
        boolean enabled = ProviderManager.isKaeEnabled();
        if (ProviderManager.currentProvider().equals("KAEProvider")) {
            assertTrue(enabled);
        } else {
            assertFalse(enabled);
        }
    }

    @Test
    public void testGetProviderSingleton() {
        Provider p1 = ProviderManager.getProvider();
        Provider p2 = ProviderManager.getProvider();
        assertNotNull(p1);
        assertTrue(p1 == p2);
    }

    @Test
    public void testGetBcProviderSingleton() {
        Provider p1 = ProviderManager.getBcProvider();
        Provider p2 = ProviderManager.getBcProvider();
        assertTrue(p1 == p2);
    }

    @Test
    public void testKaeDisabledProperty() {
        String original = System.getProperty("crypto.sdk.disableKae");
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            Provider provider = ProviderManager.getProvider();
            assertEquals("BC", provider.getName());
            assertFalse(ProviderManager.isKaeEnabled());
        } finally {
            if (original != null) {
                System.setProperty("crypto.sdk.disableKae", original);
            } else {
                System.clearProperty("crypto.sdk.disableKae");
            }
            resetProviderCache();
        }
    }

    @Test
    public void testInitProviderFallbackToBc() {
        String original = System.getProperty("crypto.sdk.disableKae");
        try {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
            Provider provider = ProviderManager.getProvider();
            assertNotNull(provider);
            assertTrue(provider.getName().equals("BC") || provider.getName().equals("KAEProvider"));
        } finally {
            if (original != null) {
                System.setProperty("crypto.sdk.disableKae", original);
            } else {
                System.clearProperty("crypto.sdk.disableKae");
            }
            resetProviderCache();
        }
    }

    @Test
    public void testIsProviderAvailableNull() throws Exception {
        Method method = ProviderManager.class.getDeclaredMethod("isProviderAvailable", Provider.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(null, (Provider) null);
        assertFalse(result);
    }

    @Test
    public void testCreateKaeProvider() throws Exception {
        Method method = ProviderManager.class.getDeclaredMethod("createKaeProvider");
        method.setAccessible(true);
        Object result = method.invoke(null);
        assertTrue(result == null || result instanceof Provider);
    }

    @Test
    public void testCurrentProviderWithNullCache() {
        String original = System.getProperty("crypto.sdk.disableKae");
        try {
            resetProviderCache();
            String name = ProviderManager.currentProvider();
            assertNotNull(name);
            assertTrue(name.equals("BC") || name.equals("KAEProvider"));
        } finally {
            if (original != null) {
                System.setProperty("crypto.sdk.disableKae", original);
            } else {
                System.clearProperty("crypto.sdk.disableKae");
            }
            resetProviderCache();
        }
    }

    @Test
    public void testIsKaeDisabledPropertyFalse() {
        String original = System.getProperty("crypto.sdk.disableKae");
        try {
            System.setProperty("crypto.sdk.disableKae", "false");
            resetProviderCache();
            Provider provider = ProviderManager.getProvider();
            assertNotNull(provider);
            assertTrue(provider.getName().equals("BC") || provider.getName().equals("KAEProvider"));
        } finally {
            if (original != null) {
                System.setProperty("crypto.sdk.disableKae", original);
            } else {
                System.clearProperty("crypto.sdk.disableKae");
            }
            resetProviderCache();
        }
    }

    @Test
    public void testIsProviderAvailableWithBcProvider() throws Exception {
        Provider bcProvider = ProviderManager.getBcProvider();
        Method method = ProviderManager.class.getDeclaredMethod("isProviderAvailable", Provider.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(null, bcProvider);
        assertTrue(result);
    }

    @Test
    public void testIsProviderAvailableWithBrokenProvider() throws Exception {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        Method method = ProviderManager.class.getDeclaredMethod("isProviderAvailable", Provider.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(null, broken);
        assertFalse(result);
    }

    @Test
    public void testIsKaeEnabledWithBcProvider() {
        String original = System.getProperty("crypto.sdk.disableKae");
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            assertFalse(ProviderManager.isKaeEnabled());
        } finally {
            if (original != null) {
                System.setProperty("crypto.sdk.disableKae", original);
            } else {
                System.clearProperty("crypto.sdk.disableKae");
            }
            resetProviderCache();
        }
    }

    @Test
    public void testCurrentProviderReturnsBcName() {
        String original = System.getProperty("crypto.sdk.disableKae");
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            assertEquals("BC", ProviderManager.currentProvider());
        } finally {
            if (original != null) {
                System.setProperty("crypto.sdk.disableKae", original);
            } else {
                System.clearProperty("crypto.sdk.disableKae");
            }
            resetProviderCache();
        }
    }

    @Test
    public void testGetBcProviderDoubleCheck() throws Exception {
        Field field = ProviderManager.class.getDeclaredField("bcProvider");
        field.setAccessible(true);
        field.set(null, null);
        Provider p1 = ProviderManager.getBcProvider();
        assertNotNull(p1);
        Provider p2 = ProviderManager.getBcProvider();
        assertTrue(p1 == p2);
    }

    private void resetProviderCache() {
        try {
            Field field = ProviderManager.class.getDeclaredField("provider");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }
}
