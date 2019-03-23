# 1. 标准命令

- genrsa，使用RSA算法生成私钥，如：`openssl genrsa -aes256 -out ca.key 3072`。  
  - -aes256使用AES256CBC加密输出的PEM格式的私钥。  
  - -out生成的文件。  
  - numbits，私钥位数。  
- pkcs12，导入证书，如：`openssl pkcs12 -export -out etcd_client.p12 -in client.pem -inkey client.key`。提示输入私钥口令和p12口令。  
  - -export生成PKCS12文件。
  - -out outfile输出文件。
  - -in  infile输入文件。
  - -inkey file证书私钥。
- req，创建证书或证书请求，如：创建CA证书`openssl req -new -x509 -days 3650 -key  ca.key -out  ca.pem`或`openssl req -config c:\openssl\bin\openssl.cnf -new -x509 -keyout ca-key.pem.txt -out ca-certificate.pem.txt -days 365`，创建证书请求`openssl req -new -key server.key -out server.csr`。  
  - -config file请求模板文件，可添加subjectAltName中的DNS和IP。
  - -new新请求。
  - -x509直接生成证书。
  - -days有效期。
  - -key file证书对应的私钥。
  - -keyout file生成私钥并输出到文件。
  - -out输出文件。
- version
- x509，根据请求创建证书，如：`openssl x509 -req -days 3650 -sha256 -extensions v3_req -CA ca.pem -CAkey ca.key -in server.csr -out server.pem -CAcreateserial -extfile server.cnf`。
  - -req通过请求创建证书。
  - -days arg证书有效期。
  - -sha256签名算法。
  - -CA arg指定CA证书。
  - -CAkey arg指定CA私钥。
  - -in arg输入请求。
  - -out arg输出证书文件。
  - -outform arg输出文件格式，默认PEM，可选DER, NET。
  - -CAcreateserial生成证书序列号。
  - -extfile使用的模板文件。
  - -extensions根据模板中添加的X509V3 extensions。
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

# 2. 哈希命令

- md5  
- sha1

# 3. 加密命令

- aes-256-cbc
- base64
