package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.enums.AccessPointType;
import org.junit.Assert;
import org.junit.Test;

public class AccessPointTypeTest {

    @Test
    public void testGetDisplayNameByCode_ECS() {
        Assert.assertEquals("ECS", AccessPointType.getDisplayNameByCode(1));
    }

    @Test
    public void testGetDisplayNameByCode_Custom() {
        Assert.assertEquals("Custom", AccessPointType.getDisplayNameByCode(2));
    }

    @Test
    public void testGetDisplayNameByCode_CCE() {
        Assert.assertEquals("CCE", AccessPointType.getDisplayNameByCode(3));
    }

    @Test
    public void testGetDisplayNameByCode_Unknown() {
        Assert.assertEquals("Unknown", AccessPointType.getDisplayNameByCode(999));
        Assert.assertEquals("Unknown", AccessPointType.getDisplayNameByCode(0));
        Assert.assertEquals("Unknown", AccessPointType.getDisplayNameByCode(-1));
    }

    @Test
    public void testEnumValues() {
        Assert.assertEquals(1, AccessPointType.ECS.getCode());
        Assert.assertEquals("ECS", AccessPointType.ECS.getDisplayName());
        Assert.assertEquals(2, AccessPointType.CUSTOM.getCode());
        Assert.assertEquals("Custom", AccessPointType.CUSTOM.getDisplayName());
        Assert.assertEquals(3, AccessPointType.CCE.getCode());
        Assert.assertEquals("CCE", AccessPointType.CCE.getDisplayName());
    }

    @Test
    public void testAllValues() {
        AccessPointType[] values = AccessPointType.values();
        Assert.assertEquals(3, values.length);
    }
}
