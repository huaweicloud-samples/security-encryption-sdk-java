package com.huaweicloud.encryptionsdk;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.log.LogConfig;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class HuaweiConfig {

    private String ak;

    private String sk;

    /**
     * 是否开启自寻region KeyRing
     */
    private boolean isDiscovery;

    private List<KMSConfig> kmsConfigList;

    private CryptoAlgorithm cryptoAlgorithm;

    /**
     * 密钥胶囊配置（密钥胶囊模式时使用）
     */
    private KeyCapsuleConfig keyCapsuleConfig;

    /**
     * 日志配置
     */
    private LogConfig logConfig;

    /**
     * 是否仅本地打印日志（不上报LTS）
     * true=日志仅在本地打印，不需要配置LogConfig
     * false=正常日志上报模式，需要配置LogConfig（默认false）
     */
    @Builder.Default
    private boolean localLogOnly = false;

    public void setAk(String ak) {
        if (Utils.isEmpty(ak)) {
            throw new HuaweicloudException(ErrorMessage.AK_NULL_EXCEPTION.getMessage());
        }
        this.ak = ak;
    }

    public void setSk(String sk) {
        if (Utils.isEmpty(sk)) {
            throw new HuaweicloudException(ErrorMessage.AK_NULL_EXCEPTION.getMessage());
        }
        this.sk = sk;
    }
}
