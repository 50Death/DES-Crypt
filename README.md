# DES Crypt
# DES加密算法 不依赖现有的类库

## （目前网上很难找到DES加密算法完整不基于类库实现的代码）

[本文清晰的讲述了DES加密算法](https://blog.csdn.net/p312011150/article/details/80847907) 此处不再赘述

本项目采用了自己仿制的PKCS#5Padding填充，所以对明文内容是否为64位无要求

调用方式：
```java
DESCrypt descrypt = new DESCrypt();
descrypt.doFinal(加密模式,明文,密钥,是否进行BASE64编码);
//加密模式
enum crypt_mode {ENCRYPT_MODE, DECRYPT_MODE}
//是否进行BASE64
enum paraCoding {BASE64, NOBASE64}
```

## 注意事项

### JAVA版本
java version "1.8.0_191"

Java(TM) SE Runtime Environment (build 1.8.0_191-b12)

Java HotSpot(TM) 64-Bit Server VM (build 25.191-b12, mixed mode) 

### IDE
IntelliJ IDEA

### 关于PKCS5Padding

解密时没有对密文是否使用PKCS5Padding做出判断，如果解密时输入的密文由其他渠道生成可能会导致去填充出错，致使解密失败

### 关于加密密文

输出为二进制字符串，未进行任何编码

## 不求捐赠但求拿走红包

![图片加载失败](https://github.com/50Death/CipheredSocketChat/blob/master/Pictures/%E6%94%AF%E4%BB%98%E5%AE%9D%E7%BA%A2%E5%8C%85.jpg)
