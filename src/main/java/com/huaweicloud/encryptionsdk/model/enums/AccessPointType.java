package com.huaweicloud.encryptionsdk.model.enums;

public enum AccessPointType {

    ECS(1, "ECS"),
    CUSTOM(2, "Custom"),
    CCE(3, "CCE");

    private final int code;
    private final String displayName;

    AccessPointType(int code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }

    public int getCode() {
        return code;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static String getDisplayNameByCode(int code) {
        for (AccessPointType type : values()) {
            if (type.code == code) {
                return type.displayName;
            }
        }
        return "Unknown";
    }
}
