package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerate;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerateFactory;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.DataKeyGenerateType;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;

/**
 * @author zc
 * @ClassName DataKeyGenerateTest
 * @description:
 * @datetime 2022年 09月 19日 14:14
 */
public class DataKeyGenerateTest {
    /**
     * 基础认证信息：
     * 认证用的ak和sk直接写到代码中有很大的安全风险，建议在配置文件或者环境变量中密文存放，使用时解密，确保安全；
     * 本示例以ak和sk保存在环境变量中来实现身份验证为例，运行本示例前请先在本地环境中设置环境变量HUAWEICLOUD_SDK_AK和HUAWEICLOUD_SDK_SK。
     * - ACCESS_KEY: 华为云账号Access Key
     * - SECRET_ACCESS_KEY: 华为云账号Secret Access Key, 敏感信息，建议密文存储
     */
    private static final String ACCESS_KEY = System.getenv("HUAWEICLOUD_SDK_AK");

    private static final String SECRET_ACCESS_KEY = System.getenv("HUAWEICLOUD_SDK_SK");

    private static final String PROJECT_ID = "7c55d8e5238d42e49fd9ce11b24b035b";

    private static final String REGION = "cn-north-7";

    private static final String KEYID = "c1f52e49-8e5c-4772-8713-ead33ed9faa2";

    @Test
    public void Should_ok_When_LocalGenerate() throws NoSuchAlgorithmException {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.LOCAL_GENERATE);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
        System.out.println(Base64.getEncoder().encodeToString(dataKeyMaterials.getPlaintextDataKey().getEncoded()));
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSGenerate() throws NoSuchAlgorithmException {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KMS_GENERATE);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .sk(SECRET_ACCESS_KEY)
            .ak(ACCESS_KEY)
            .kmsConfigList(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID)))
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
        System.out.println(Base64.getEncoder().encodeToString(dataKeyMaterials.getPlaintextDataKey().getEncoded()));
    }
}
