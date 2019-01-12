---
title: SSL
date: 2019-01-12 19:44:27
categories: java
tags:
---

通过SSL协议保护client和server之间的通信，包含1. 服务端认证、2. 客户端认证和3. 通信数据加密，例：`https://www.onlinebooks.com/creditcardinfo.html`。  
最新的协议版本：TLS。  
认证过程通过公私钥对机制，owner对外发布公钥，并通过 **X.509证书** 来证明是该公钥的owner，保留私钥。  

# X.509证书

## 结构

- data: public key owner的DN(Distinguished Name), certificate issuer的DN, 有效期，public key  
- signature  

## 获取方式

1. 通过CA(Certificate Authority)，例VeriSign。证书颁发机构具有层级，root CA的证书自签名，下层颁发机构的证书由上层机构签名，由此构成certificate chain。  
1. 自签名：owner和issuer相同。  

# Keytool

存在于jre的bin目录下，用来管理keystore/truststore。  

keystore，客户端认证使用，主要用来存储：  
1. private key和与public key相关的客户端certificate chain
1. trusted certificates

truststore，在SSL协议中认证服务器使用，只用来存储trusted CA root self-signed certificates。  

向keystore中添加entity时需要指定全局唯一的alias。  
常见用法：  
- 生成密钥对：`-genkeypair`，若keystore不存在则自动创建。  
- 生成证书请求：`-certreq`  
- 导入证书或证书链：`-importcert`，若keystore不存在则自动创建。  
- 导出证书：`-exportcert`  
- 列出keystore中的条目：`-list`

## 创建keystore.jks

```bash
#生成密钥并在当前目录自动生成名为clientkeystore的JKS格式keystore文件。
$ keytool -keystore clientkeystore -genkey -alias client
输入密钥库口令:
再次输入新口令:
您的名字与姓氏是什么?
  [Unknown]:  Aaron
您的组织单位名称是什么?
  [Unknown]:  PAAS
您的组织名称是什么?
  [Unknown]:  IT
您所在的城市或区域名称是什么?
  [Unknown]:  Shenzhen
您所在的省/市/自治区名称是什么?
  [Unknown]:  Guangdong
该单位的双字母国家/地区代码是什么?
  [Unknown]:  CN
CN=Aaron, OU=PAAS, O=IT, L=Shenzhen, ST=Guangdong, C=CN是否正确?
  [否]:  y

输入 <client> 的密钥口令
        (如果和密钥库口令相同, 按回车):

#生成证书请求文件client.csr（PEM格式）
$ keytool -keystore clientkeystore -certreq -alias client -keyalg rsa -file client.csr
#将CSR发送给CA，由CA颁发使用CA私钥签名证书。
#导入CA颁发的证书，client.cer中包含客户端证书和CARoot.cer
$ keytool -import -keystore clientkeystore -file client.cer -alias client
#或单独导入CA证书
$ keytool -import -keystore clientkeystore -file CARoot.cer -alias theCARoot

########

#生成密钥对和自签名证书
$ keytool -genkey -keyalg RSA -alias CAPS -keystore keystore_filename
#导出自签名证书
$ keytool -export -alias CAPS -keystore keystore_filename -rfc -file self_signed_cert_filename
#导入信任的CA证书
$ keytool -import -trustcacerts -alias CAPS -file ca-certificate-filename -keystore keystore_filename
```

> **Tips:** 某些CA会校验first and last name是否为正确的domain。

## 创建truststore.jks

```bash
#在当前目录生成myTrustStore，将信任的CA证书通过别名firstCA导入到truststore
$ keytool -import -file C:\cascerts\firstCA.cert -alias firstCA -keystore myTrustStore
```

# OpenSSL，http://www.openssl.org

SSL/TLS协议的开源实现，可用命令：  
- pkcs12，解析或生成PKCS #12文件  
- req，创建或处理证书请求（PKCS #10格式）  

PKCS #12，keystore存档文件格式，扩展名.p12或.pfx，在一个文件中存储多个加密对象，通常打包一个私钥及有关的X.509证书，文件本身也是加密的。  
通过OpenSSL的`openssl pkcs12 [options]`命令创建/解析，例：  
- 解析p12文件并输出证书：`openssl pkcs12 -in file.p12 -out file.pem`  
- 仅输出客户端证书：`openssl pkcs12 -in file.p12 -clcerts -out file.pem`  
- 不加密私钥：`openssl pkcs12 -in file.p12 -out file.pem -nodes`  
- 创建p12文件：`openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate"`，file.pem包含私钥和证书。  
- 添加多个证书：`openssl pkcs12 -export -in file.pem -out file.p12 -name "My Certificate" -certfile othercerts.pem`  
- 创建CA证书：`openssl  req  -config c:\openssl\bin\openssl.cnf -new  -x509  -keyout  ca-key.pem.txt -out  ca-certificate.pem.txt  -days  365`  
- 使用CA证书签名服务器证书：`openssl  x509  -req  -CA ca-certificate.pem.txt -CAkey ca-key.pem.txt -in client.csr -out client.cer  -days 365  -CAcreateserial`  

> **Tips:** keytool只能读取pkcs12（在export时添加-noiter -nomaciter），无法写入。

# 配置server.xml

修改Connector中的keystoreFile和keystorePass，如：

```xml
<Connector port="8443"
   maxThreads="150" minSpareThreads="25" maxSpareThreads="75"
   enableLookups="false" disableUploadTimeout="true"
   keystoreFile="C:\JavaCAPS6\keystore\keystore.jks"
   keystorePass="changeit"
   acceptCount="100" debug="0" scheme="https" secure="true"
   clientAuth="false" sslProtocol="TLS" />
```

# 修改Java启动参数

增加truststore路径，如：`set JAVA_OPTS=-Xmx512m -Djavax.net.ssl.trustStore=C:\JavaCAPS\keystore\cacerts.jks`

# TLS协商过程

1. 客户端发出请求（ClientHello）：携带支持的协议版本如TLSv1.2，支持的加密算法如ECDHE&RSAwithAES128GCM&SHA256，随机数1，[请求域名]。  
1. 服务器响应（ServerHello）：确认使用的加密通信协议版本如TLSv1.2，使用的加密算法如RSAwithAES128GCM&SHA256，服务器证书，随机数2，[客户端证书请求，如金融机构请求提供USB-KEY中的客户端证书]，[session ID/session ticket(encrypted session key)]。  
1. 客户端响应：验证服务器证书（通过客户端保存的可信CA列表中证书公钥解密服务器证书中的签名，证书中的域名和实际域名是否一致，证书是否过期），取出服务器证书中的公钥加密随机数3(pre-master secret)，加密通信隧道通知，握手结束通知（所有内容HASH），[客户端证书]。之后使用三个随机数生成对称密钥R。  
1. [校验客户端证书]，接收到加密随机数3，使用私钥解密，使用三个随机数生成对称密钥R。发出加密通信隧道通知，握手结束通知（所有内容的HASH）。

# 证书校验过程

1. 取上级证书的公钥，对下级证书的签名进行解密，得出下级证书的摘要digest1  
1. 对下级证书进行信息摘要digest2  
1. 判断digest1和digest2是否相等  
1. 依次对各级相邻证书校验，直到root CA或可信锚点  


参考：<https://docs.oracle.com/cd/E19509-01/820-3503/index.html>
