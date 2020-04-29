# 0xFF_字符编码

## ASCII

一个字节(BYTE)有 {==8==} 位二进制(bit)，可表示范围 {==0~255==} = {==0xFF==}。

ASCII采用 {==7==} 位（第一位为0）, {==128==} 个值（0~127）编码26个英文字母、10个数字、32个特殊字符、33个控制字符和1个空格。其中：

+ `{==0~31 / 0x00~0x1F==}` 和 {==127 / 0x7F==} 共 {==33==} 个，代表控制字符，不可显示。如:
    - 8 = BS（退格）
    - 9 = HT（水平制表符）
    - 10 = LF（换行）
    - 13 = CR（回车）
    - 127 = DEL（删除）

    !!! tip "回车`\r`使光标重新回到本行开头，换行`\n`使光标往下一行。Windows中使用`\r\n`，UNIX中使用`\n`，MAC中使用`\r`。"

+ {==32 / 0x20==}，代表空格
+ `{==33~47 / 0x21~0x2F==}`、`{==58~64 / 0x3A~0x40==}`、`{==91~96 / 0x5B~0x60==}`、`{==123~126 / 0x7B~0x7E==}` 共 {==32==} 个，代表`` `~!@#$%^&*()-_=+\|[{}];:'",<.>/? ``特殊字符
+ `{==48~57 / 0x30~0x39==}`共 {==10==} 个，代表0~9数字
+ `{==65~90 / 0x41~0x5A==}`共 {==26==} 个，代表A~Z大写字母
+ `{==97~122 / 0x61~0x7A==}`共 {==26==} 个，代表a~z小写字母


## ISO-8859-1(Latin-1)

单字节编码，`0x00~0x7F`为ASCII编码，其他为欧洲语言。


## GB2312

{==简体中文==} 编码方式，使用 {==两个字节==} 代表一个汉字，可表示范围`{==0~65535==}`。

> 英文字母和ISO-8859-1一致。

## GBK

包含简体中文和繁体中文。

## ANSI

Windows默认的编码方式，扩展了ASCII编码，使用`0x00~0x7F`表示ASCII编码，`0x80~0xFFFF`表示其他语言的字符。

!!! warning "不同语言与ANSI编码不能互相转换，比如 GB2312 != ANSI"


## Unicode

统一字符编码，规定了所有字符与二进制的对应关系。

> 字符串在Java内存中总是按Unicode编码存储。

### 存储方式

#### UCS-2

直接使用两个字节存储Unicode编码。

+ little endian，小头方式（倒序），即低8位在前，高8位在后。文件中BOM前两个字节是FF FE表示。
+ big endian，大头方式（正序），文件中BOM前两个字节是FE FF表示。

> BOM在Windows中是字节顺序标记，用来区分大头还是小头。


#### UTF-8

Unicode字符在计算机中的存储方式，使用1~4个字节 {==变长存储==}。文件中BOM前三个字节是EF BB BF表示。

+ 对于单字节符号，第一位为0，后7位为Unicode编码。对于英文字母，UTF-8 = ASCII。
+ 对于n字节符号，第一个字节前n位为1，n+1位为0，后面字节前两位为10，其他位为Unicode编码。

| Unicode符号范围（十六进制） | UTF-8编码方式（二进制） |
| --- | --- |
| 0000 0000-0000 007F | 0xxxxxxx |
| 0000 0080-0000 07FF | 110xxxxx 10xxxxxx |
| 0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx |
| 0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx |

!!! info "一个中文汉字使用ANSI占 {==2==} 个字节, 使用GB2312占 {==2==} 个字节, 使用Unicode UCS带BOM占 {==4==} 个字节(汉字占 {==2==} 个), 使用Unicode UTF-8占 {==3==} 个字节, 带BOM占 {==6==}个字节(汉字占 {==3==} 个)"

??? note "ASCII控制字符"
    | 二进制 | 十进制 | 十六进制 | 缩写 | 名称/意义 |
    | --- | --- | --- | --- | --- |
    | 0000 0000 | 0 | 00 | NUL | 空字符（Null） |
    | 0000 0001 | 1 | 01 | SOH | 标题开始 |
    | 0000 0010 | 2 | 02 | STX | 本文开始 |
    | 0000 0011 | 3 | 03 | ETX | 本文结束 |
    | 0000 0100 | 4 | 04 | EOT | 传输结束 |
    | 0000 0101 | 5 | 05 | ENQ | 请求 |
    | 0000 0110 | 6 | 06 | ACK | 确认回应 |
    | 0000 0111 | 7 | 07 | BEL | 响铃 |
    | 0000 1000 | 8 | 08 | BS | 退格 |
    | 0000 1001 | 9 | 09 | HT | 水平定位符号 |
    | 0000 1010 | 10 | 0A | LF | 换行键 |
    | 0000 1011 | 11 | 0B | VT | 垂直定位符号 |
    | 0000 1100 | 12 | 0C | FF | 换页键 |
    | 0000 1101 | 13 | 0D | CR | 归位键 |
    | 0000 1110 | 14 | 0E | SO | 取消变换（Shift out） |
    | 0000 1111 | 15 | 0F | SI | 启用变换（Shift in） |
    | 0001 0000 | 16 | 10 | DLE | 跳出数据通讯 |
    | 0001 0001 | 17 | 11 | DC1 | 设备控制一（XON 启用软件速度控制） |
    | 0001 0010 | 18 | 12 | DC2 | 设备控制二 |
    | 0001 0011 | 19 | 13 | DC3 | 设备控制三（XOFF 停用软件速度控制） |
    | 0001 0100 | 20 | 14 | DC4 | 设备控制四 |
    | 0001 0101 | 21 | 15 | NAK | 确认失败回应 |
    | 0001 0110 | 22 | 16 | SYN | 同步用暂停 |
    | 0001 0111 | 23 | 17 | ETB | 区块传输结束 |
    | 0001 1000 | 24 | 18 | CAN | 取消 |
    | 0001 1001 | 25 | 19 | EM | 连接介质中断 |
    | 0001 1010 | 26 | 1A | SUB | 替换 |
    | 0001 1011 | 27 | 1B | ESC | 跳出 |
    | 0001 1100 | 28 | 1C | FS | 文件分割符 |
    | 0001 1101 | 29 | 1D | GS | 组群分隔符 |
    | 0001 1110 | 30 | 1E | RS | 记录分隔符 |
    | 0001 1111 | 31 | 1F | US | 单元分隔符 |
    | 0111 1111 | 127 | 7F | DEL | 删除 |

??? note "ASCII可显示字符"
    | 二进制 | 十进制 | 十六进制 | 图形 |
    | --- | --- | --- | --- |
    | 0010 0000 | 32 | 20 | （空格） |
    | 0010 0001 | 33 | 21 | ! |
    | 0010 0010 | 34 | 22 | " |
    | 0010 0011 | 35 | 23 | # |
    | 0010 0100 | 36 | 24 | $ |
    | 0010 0101 | 37 | 25 | % |
    | 0010 0110 | 38 | 26 | & |
    | 0010 0111 | 39 | 27 | ' |
    | 0010 1000 | 40 | 28 | ( |
    | 0010 1001 | 41 | 29 | ) |
    | 0010 1010 | 42 | 2A | * |
    | 0010 1011 | 43 | 2B | + |
    | 0010 1100 | 44 | 2C | , |
    | 0010 1101 | 45 | 2D | - |
    | 0010 1110 | 46 | 2E | . |
    | 0010 1111 | 47 | 2F | / |
    | 0011 0000 | 48 | 30 | 0 |
    | 0011 0001 | 49 | 31 | 1 |
    | 0011 0010 | 50 | 32 | 2 |
    | 0011 0011 | 51 | 33 | 3 |
    | 0011 0100 | 52 | 34 | 4 |
    | 0011 0101 | 53 | 35 | 5 |
    | 0011 0110 | 54 | 36 | 6 |
    | 0011 0111 | 55 | 37 | 7 |
    | 0011 1000 | 56 | 38 | 8 |
    | 0011 1001 | 57 | 39 | 9 |
    | 0011 1010 | 58 | 3A | : |
    | 0011 1011 | 59 | 3B | ; |
    | 0011 1100 | 60 | 3C | < |
    | 0011 1101 | 61 | 3D | = |
    | 0011 1110 | 62 | 3E | > |
    | 0011 1111 | 63 | 3F | ? |
    | 0100 0000 | 64 | 40 | @ |
    | 0100 0001 | 65 | 41 | A |
    | 0100 0010 | 66 | 42 | B |
    | 0100 0011 | 67 | 43 | C |
    | 0100 0100 | 68 | 44 | D |
    | 0100 0101 | 69 | 45 | E |
    | 0100 0110 | 70 | 46 | F |
    | 0100 0111 | 71 | 47 | G |
    | 0100 1000 | 72 | 48 | H |
    | 0100 1001 | 73 | 49 | I |
    | 0100 1010 | 74 | 4A | J |
    | 0100 1011 | 75 | 4B | K |
    | 0100 1100 | 76 | 4C | L |
    | 0100 1101 | 77 | 4D | M |
    | 0100 1110 | 78 | 4E | N |
    | 0100 1111 | 79 | 4F | O |
    | 0101 0000 | 80 | 50 | P |
    | 0101 0001 | 81 | 51 | Q |
    | 0101 0010 | 82 | 52 | R |
    | 0101 0011 | 83 | 53 | S |
    | 0101 0100 | 84 | 54 | T |
    | 0101 0101 | 85 | 55 | U |
    | 0101 0110 | 86 | 56 | V |
    | 0101 0111 | 87 | 57 | W |
    | 0101 1000 | 88 | 58 | X |
    | 0101 1001 | 89 | 59 | Y |
    | 0101 1010 | 90 | 5A | Z |
    | 0101 1011 | 91 | 5B | [ |
    | 0101 1100 | 92 | 5C | \ |
    | 0101 1101 | 93 | 5D | ] |
    | 0101 1110 | 94 | 5E | ^ |
    | 0101 1111 | 95 | 5F | _ |
    | 0110 0000 | 96 | 60 | \` |
    | 0110 0001 | 97 | 61 | a |
    | 0110 0010 | 98 | 62 | b |
    | 0110 0011 | 99 | 63 | c |
    | 0110 0100 | 100 | 64 | d |
    | 0110 0101 | 101 | 65 | e |
    | 0110 0110 | 102 | 66 | f |
    | 0110 0111 | 103 | 67 | g |
    | 0110 1000 | 104 | 68 | h |
    | 0110 1001 | 105 | 69 | i |
    | 0110 1010 | 106 | 6A | j |
    | 0110 1011 | 107 | 6B | k |
    | 0110 1100 | 108 | 6C | l |
    | 0110 1101 | 109 | 6D | m |
    | 0110 1110 | 110 | 6E | n |
    | 0110 1111 | 111 | 6F | o |
    | 0111 0000 | 112 | 70 | p |
    | 0111 0001 | 113 | 71 | q |
    | 0111 0010 | 114 | 72 | r |
    | 0111 0011 | 115 | 73 | s |
    | 0111 0100 | 116 | 74 | t |
    | 0111 0101 | 117 | 75 | u |
    | 0111 0110 | 118 | 76 | v |
    | 0111 0111 | 119 | 77 | w |
    | 0111 1000 | 120 | 78 | x |
    | 0111 1001 | 121 | 79 | y |
    | 0111 1010 | 122 | 7A | z |
    | 0111 1011 | 123 | 7B | { |
    | 0111 1100 | 124 | 7C | 竖线 |
    | 0111 1101 | 125 | 7D | } |
    | 0111 1110 | 126 | 7E | ~ |


## 加解密

### 摘要

```java
try {
    // 初始化哈希算法
    MessageDigest digest = MessageDigest.getInstance("SHA-1");  // or MD5

    String msg = "This is a message.";
    // 计算摘要
    digest.update(msg.getBytes(StandardCharsets.UTF_8));
    byte[] hash = digest.digest();
    // MD5: 16, SHA-1: 20
    LOG.info("hash length: " + hash.length);
    LOG.info(Base64.getEncoder().encodeToString(hash));
} catch (Exception e) {
    LOG.severe(e.toString());
}
```

### 口令哈希/密钥导出

```java
try {
    String password = "Admin@123";
    // 随机盐值
    byte[] salt = new byte[8];
    SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
    // 迭代次数
    final int ITERATE_COUNT = 10000;
    // 输出长度
    final int OUTPUT_LEN = 256;
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
            ITERATE_COUNT, OUTPUT_LEN);
    SecretKeyFactory factory = SecretKeyFactory
            .getInstance("PBKDF2WithHmacSHA256");
    byte[] encodedPassword = factory.generateSecret(spec).getEncoded();
    LOG.info("口令哈希/密钥导出: " + encodedPassword.length);
} catch (Exception e) {
    LOG.severe(e.toString());
}
```

### 非对称算法签名和验证

```java
try {
    // 生成密钥对
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048, new SecureRandom());
    KeyPair kp = generator.generateKeyPair();

    // --------
    PublicKey publicKey = kp.getPublic();
    // 公钥X.509编码
    byte[] x509Encoded = publicKey.getEncoded();
    // 解码
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(x509Encoded);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey decodedPublicKey = keyFactory.generatePublic(pubKeySpec);

    PrivateKey privateKey = kp.getPrivate();
    // 私钥PKCS#8编码
    byte[] pkcsEncoded = privateKey.getEncoded();
    // 解码
    PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(pkcsEncoded);
    PrivateKey decodedPrivatekey = keyFactory.generatePrivate(priKeySpec);
    // --------

    // 初始化签名算法
    Signature signature = Signature.getInstance("SHA256withRSA");
    // 使用私钥签名
    signature.initSign(kp.getPrivate());
    String information = "This is an important information.";
    signature.update(information.getBytes(StandardCharsets.UTF_8));
    byte[] sign = signature.sign();
    // 256
    LOG.info("sign length: " + sign.length);
    LOG.info(Base64.getEncoder().encodeToString(sign));

    // 使用公钥验证
    signature.initVerify(kp.getPublic());
    signature.update(information.getBytes(StandardCharsets.UTF_8));
    LOG.info("Verify: " + signature.verify(sign));
} catch (Exception e) {
    LOG.severe(e.toString());
}
```

### AES加解密

```java
try {
    // 随机生成AES key
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(new SecureRandom());
    Key key = generator.generateKey();

    // --------
    // 编码
    byte[] encodedKey = key.getEncoded();
    // 解码
    SecretKeySpec keySpec = new SecretKeySpec(encodedKey, "AES");
    SecretKey decodedKey = keySpec;
    // --------

    // 初始化加密算法
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    String plainText = "This is a secret.";
    // 加密
    byte[] cipherTextBytes = cipher
            .doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    LOG.info(Base64.getEncoder().encodeToString(cipherTextBytes));

    // 初始化解密算法
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
    LOG.info(new String(plainTextBytes));
} catch (Exception e) {
    LOG.severe(e.toString());
}
```

```java
try {
    // 随机生成AES key
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(new SecureRandom());
    Key key = generator.generateKey();

    // 随机生成初始向量
    final int GCM_IV_LEN = 12;
    byte[] initVector = new byte[GCM_IV_LEN];
    (new SecureRandom()).nextBytes(initVector);

    final int GCM_TAG_LEN = 16;
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LEN * Byte.SIZE,
            initVector);

    // 初始化加密算法
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);

    String msg = "This is a secret.";
    byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
    // 计算输出长度
    int outputLen = cipher.getOutputSize(msgBytes.length);
    byte[] cipherBytes = Arrays.copyOf(initVector, GCM_IV_LEN + outputLen);
    cipher.doFinal(msgBytes, 0, msgBytes.length, cipherBytes, GCM_IV_LEN);
    LOG.info("cipherText: " + cipherBytes.length);

    // 解密
    cipher.init(Cipher.DECRYPT_MODE, key, spec);
    byte[] plainBytes = cipher.doFinal(cipherBytes, GCM_IV_LEN, outputLen);
    LOG.info(new String(plainBytes));
} catch (Exception e) {
    LOG.severe(e.toString());
}
```

### DES加密再BASE64

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

private final static String DES_KEY = "xxxxxxxx";

Key key = new SecretKeySpec(DES_KEY.getBytes(), "DES");
Cipher cipher = null;
try {
    cipher = Cipher.getInstance("DES");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
} catch (Exception e) {
    e.printStackTrace();
}
```
