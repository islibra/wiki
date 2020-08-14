# OpenSSL

查看 OpenSSL 版本: `openssl version`

## I. 标准命令

```
asn1parse         ca                ciphers           cms
crl               crl2pkcs7         dgst              dh
dhparam           dsa               dsaparam          ec
ecparam           enc               engine            errstr
gendh             gendsa            genpkey           genrsa
nseq              ocsp              passwd            pkcs12
pkcs7             pkcs8             pkey              pkeyparam
pkeyutl           prime             rand              req
rsa               rsautl            s_client          s_server
s_time            sess_id           smime             speed
spkac             ts                verify            version
x509
```

### II. genrsa

#### III. 使用 RSA 算法生成私钥

```sh
# -out, 生成的私钥文件名。
# -aes256, 使用 AES256CBC 加密输出的 PEM 格式的私钥。
# -passout, 加密私钥的口令。
# numbits, RSA 私钥位数。
openssl genrsa -out ca.key -aes256 -passout pass:xxx 4096
```

### II. rsa

#### III. 解密私钥

```sh
openssl rsa -out plaintext_ca.key -in ca.key -passin pass:xxx
```

### II. req

#### III. 使用私钥直接创建 CA 证书

```sh
# -key 使用的私钥
openssl req -new -x509 -out ca.cer -days 3650 -key ca.key -passin pass:xxx -subj "/C=CN/ST=GuangDong/L=ShenZhen/O=xxx/OU=xxx/CN=xxx"
```

#### III. 使用私钥创建证书请求

```sh
openssl req -new -out client.csr -key client.key -keyform PEM -passin pass:xxx -subj "/C=CN/ST=Guangdong/L=Shenzhen/O=xxx/OU=xxx/CN=xxx"
```


- 或`openssl req -config c:\openssl\bin\openssl.cnf -new -x509 -keyout ca-key.pem.txt -out ca-certificate.pem.txt -days 365`  
    - -config file请求模板文件，可添加subjectAltName中的DNS和IP。
    - -new新请求。
    - -x509直接生成证书。
    - -days有效期。
    - -key file证书对应的私钥。
    - -keyout file生成私钥并输出到文件。
    - -out输出文件。


### II. x509

#### III. 使用证书请求和 CA 私钥签名生成证书

```sh
# -req 通过请求创建证书。
# -extfile 使用的模板文件。
# -extensions 生成 X509 V3 版本证书的必要条件。
# -days arg 证书有效期。
# -sha256 签名算法。
# -CAkey arg 指定 CA 私钥。
# -CA arg 指定 CA 证书。
# -signkey 用来签名的私钥文件。
# -in arg 输入请求。
# -out arg 输出证书文件。
# -outform arg 输出文件格式，默认PEM，可选DER, NET。
# -CAcreateserial 生成证书序列号。
openssl x509 -req -extfile /etc/pki/tls/openssl.cnf -extensions v3_req -days 3650 -sha256 -CAkey ca.key -passin pass:xxx -CA ca.cer -in server.csr -out server.cer -CAcreateserial
```

#### III. 查看证书内容

```sh
openssl x509 -in ca.cer -text -noout
```

!!! quote "[openssl 生成X509 V3的根证书及签名证书](https://blog.csdn.net/xiangguiwang/java/article/details/80333728)"


### II. pkcs12

#### III. 生成密钥库并将私钥和证书导入

```sh
# -export, 生成 PKCS12 文件。
# -out outfile, 输出文件名。
# -passout pass:xxx, 密钥库口令
# -in infile, 待导入的证书。
# -inkey file, 待导入的证书私钥。
# -passin pass:xxx, 待导入的证书私钥口令
# -certfile file, 待导入的 CA 证书
openssl pkcs12 -export -out client.p12 -passout pass:xxx -in client.cer -inkey client.key -passin pass:xxx -certfile ca.cer
```


- ecparam，生成ec密钥参数，如`openssl ecparam -genkey -name prime256v1 -out ca.pem`。
    - -genkey生成ec key。
    - -name arg
    - -out arg输出文件名称，默认stdout。
- ec，生成ec密钥，如`openssl ec -in ca.pem -out ca.key -aes256`。
    - -in arg输入文件。
    - -out arg输出文件。
    - -aes256使用AES256CBC加密输出的PEM格式的私钥。
- cms
    - -verify校验由证书签名的内容。
    - -certfile file证书文件。
    - -CAfile file信任的根证书文件。
    - -inform arg输入格式，默认SMIME，可选PEM, DER。
    - -nosmimecap
    - -nodetach使用opaque签名。
    - -nocerts签名时不包含签发者证书。
    - -noattr不包含签名属性。


## I. 哈希命令

```
md2               md4               md5               rmd160
sha               sha1
```

- md5  
- sha1

## I. 加密命令

```
aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb
aes-256-cbc       aes-256-ecb       base64            bf
bf-cbc            bf-cfb            bf-ecb            bf-ofb
camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  camellia-192-ecb
camellia-256-cbc  camellia-256-ecb  cast              cast-cbc
cast5-cbc         cast5-cfb         cast5-ecb         cast5-ofb
des               des-cbc           des-cfb           des-ecb
des-ede           des-ede-cbc       des-ede-cfb       des-ede-ofb
des-ede3          des-ede3-cbc      des-ede3-cfb      des-ede3-ofb
des-ofb           des3              desx              idea
idea-cbc          idea-cfb          idea-ecb          idea-ofb
rc2               rc2-40-cbc        rc2-64-cbc        rc2-cbc
rc2-cfb           rc2-ecb           rc2-ofb           rc4
rc4-40            rc5               rc5-cbc           rc5-cfb
rc5-ecb           rc5-ofb           seed              seed-cbc
seed-cfb          seed-ecb          seed-ofb          zlib
```

- aes-256-cbc
- base64
