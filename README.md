## 加密SDK概述

​	    加密SDK（Encryption SDK）是一个客户端密码库，提供了数据的加解密、文件流加解密等功能，旨在帮助客户专注于应用程序的核心功能，而不用关心数据加密和解密的实现过程。SDK 支持KMS密钥环、本地密钥环加密等多种加密方式，并能够支持KMS 跨地域级的容灾。用户只需调用加解密接口即可轻松实现海量数据加解密。当前本项目搬迁至[这里](https://gitcode.com/HuaweiCloudDeveloper/huaweicloud-encryption-sdk-java/overview)



## 功能特性和产品优势

- ### 极简加解密服务

数据加解密实现过程由 Encryption SDK 进行封装，用户仅需提供主密钥信息相关必要信息和调用加解密接口可实现本地海量数据加解密。

- ### 一话一密

默认情况下（未使用数据密钥缓存），Encryption SDK为它加密的每个数据对象生成唯一的数据密钥，遵循在每个加密操作中使用唯一数据密钥的加密最佳实践。

- ### 集成KMS托管保护密钥

Encryption SDK集成了KMS服务，可以指定由华为云 KMS 生成的数据加密密钥，并由主密钥加密保护。华为云KMS通过使用硬件安全模块HSM（Hardware Security Module, HSM）保护密钥的安全，所有的用户主密钥（MasterKey）都由HSM中的根密钥保护，避免主密钥泄露，满足安全与合规要求。

- ### 支持本地主密钥加密

Encryption SDK支持用户本地提供主密钥进行数据加解密。

- ### 支持多种加密算法

Encryption SDK同时支持对称加密和非对称加密算法，不同填充类型，具体算法支持AES、RSA、国密SM2和SM4等加密方式。

- ### 提供数据密钥缓存机制

Encryption SDK 具备 DEK 缓存管理功能，将 DEK 缓存在本地，用户选择使用缓存机制能够有效降低加密过程中导致的性能损耗。同时，缓存提供了最大使用次数，最大使用字节数，过期时间三个参数限定每一个数据密钥的使用，使数据密钥的不定期轮换，提高加解密的安全性。

- ### 支持多主密钥及跨地域容灾

Encryption SDK 支持同时使用多个主密钥进行数据加解密，数据加解密可指定多个 KMS主密钥（建议指定不同region的 KMS），任意 KMS均可解密 DEK 从而对数据进行解密，从而保证数据跨地域可用和灾备能力。



## 加密SDK接入指南

### 一、SDK获取和安装

- #### 本地安装

1.下载sdk代码，编译打包

```bash
git clone https://github.com/HuaweiCloudDeveloper/huaweicloud-encryption-sdk-java.git
cd EncryptionSDK
mvn clean install -DskipTests
```

2.项目中添加打包依赖

```markup
<dependency>
	<groupId>com.huaweicloud.sdk</groupId>
	<artifactId>huaweicloud-encryption-sdk-java</artifactId>
	<version>1.0.16</version>  
</dependency>
```

### 二、加解密示例

- ### 1.KMS加解密

  KMS加解密支持单一region、跨region两种加解密方式

```
参考 KmsEncryptionExample.java 示例
```

- ### 2.KMSDiscoveryKeyring密钥环

  KMSDiscoveryKeyring仅支持解密，开启后，解密无需再传递keyId，regionId，projectId等信息，仅需ak，sk即可

```
参考 KmsDiscoveryEncryptionExample.java 示例
```

- ### 3.本地对称主密钥数据加解密

```
参考 LocalAesKeyringEncryptionExample.java 示例
```

- ### 4.文件加解密

  可通过本地、kms和是否支持数据密钥缓存组合多种加密模式，包括支持本地主密钥文件加解密，kms主密钥文件加解密，本地主密钥支持缓存的文件加解

密，kms主密钥支持缓存的文件加解密。

```
参考 FileEncryptionExample.java 示例
```

