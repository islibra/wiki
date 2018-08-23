---
title: 使用HttpClient发送HTTPS请求
date: 2018-07-29 10:04:01
categories: java
tags:
---

# 一、背景知识

## TLS协商过程

1. 客户端发送HTTPS请求ClientHello
2. 服务器发送X.509证书，包含服务器公钥ServerHello
3. 客户端校验证书，并生成随机对称密钥，并用服务器公钥加密
4. 使用对称密钥加密会话数据

## Java默认存放CA证书的文件

文件路径：`%JAVA_HOME%\jre\lib\security\cacerts`

使用`KeyStore Explorer`查看，默认密码`changeit`

PEM格式，纯文本，使用BASE64编码，使用`-----BEGIN CERTIFICATE-----` 和 `-----END CERTIFICATE-----` 来标识；
DER格式，二进制。

KeyStore/TrustStore存储：1、Certificate证书；2、PrivateKey非对称加密私钥；3、SecretKey对称加密密钥。
KeyStore文件格式：JKS、JCEKS、PKCS12、DKS

## 类使用链

KeyManagerFactory/TrustManagerFactory -> KeyManager/TrustManager;SecureRandom -> SSLContext -> SSLServerSocketFactory/SSLSocketFactory -> SSLServerSocket -> SSLSocket;SSLEngine -> SSLSession

## 通过keytool查看KeyStore文件

`keytool -list -keystore cacerts`

## 将证书导入文件

`keytool -import -alias 12306 -keystore cacerts -file 12306.cer`

# 二、实现过程

## 1. 添加Maven依赖

```xml
        <dependency>
            <groupId>org.apache.httpcomponents</groupId>
            <artifactId>httpclient</artifactId>
            <version>4.5.2</version>
        </dependency>
```

## 2. 加载KeyStore

```java
String keyStoreFilePath = "";
String password = "";
KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
FileInputStream fin = new FileInputStream(keyStoreFilePath);
ks.load(fin, password.toCharArray());
```

## 3. 使用KeyStore初始化TrustManagerFactory

```java
TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
tmf.init(ks);
```

## 4. 自定义TrustManager，信任所有服务器证书

```java
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };
```

## 5. SSL上下文

```java
SSLContext sslcontext = SSLContext.getInstance("TLSv1.2");
sslcontext.init(null, trustAllCerts, null);  //信任所有证书
sslcontext.init(null, tmf.getTrustManagers(), null);  //使用加载的KeyStore
```

## 6. 创建SSLSocketFactory

```java
SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);
```

## 7. 创建请求客户端

```java
CloseableHttpClient httpclient = null;
//httpclient = HttpClients.createDefault();
httpclient = HttpClients.custom()
.setSSLSocketFactory(sslsf)  //自定义SSL工厂
.build();
```

## 8. GET请求

```java
            //创建GET方法
            HttpGet httpGet = new HttpGet("http://3ms.huawei.com/hi/home/index.html");
            
            //添加请求头
            httpGet.setHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) ...");
            
            //执行HTTP请求
            String responseBody = httpclient.execute(httpGet, response -> {
                //返回状态码
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    //返回实体
                    HttpEntity entity = response.getEntity();
                    return entity != null ? EntityUtils.toString(entity, "UTF-8") : null;  //避免中文乱码
                } else {
                    throw new ClientProtocolException("Unexpected response status: " + status);
                }
            });
            System.out.println(responseBody);
            System.out.println("--------------------GET END--------------------");
```

> **注意：**如果使用Vertx发送请求，写body时方法参数指定的编码非目的编码（UTF-8），而是当前编码（ISO-8859-1）。

```java
HttpClient httpClient = VertxUtils.getHttpClient(XXX);

HttpClientRequest request = httpClient.request(method, port, host, uri);

request.putHeader(HttpHeaders.CONTENT_TYPE, "application/json;charset=utf8");
request.putHeader(HttpHeaders.CONTENT_LENGTH, requestBody.length() + "");
request.write(requestBody, "ISO-8859-1");  //当前编码
```

## 9. POST请求

```java
            //创建POST方法
            HttpPost httpPost = new HttpPost("http://talk.page.huawei.com");
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("username", "vip"));
            nvps.add(new BasicNameValuePair("password", "secret"));
            //创建请求实体
            httpPost.setEntity(new UrlEncodedFormEntity(nvps));
            //String parameter = "key=value";
            //httpPost.setEntity(new StringEntity(parameter, ContentType.create("application/x-www-form-urlencoded")));
            //执行HTTP请求
            CloseableHttpResponse response = httpclient.execute(httpPost);
            HttpEntity entity = response.getEntity();
            if(entity != null) {
                System.out.println(entity.getContentLength());
                InputStream in = entity.getContent();
                BufferedReader br = new BufferedReader(new InputStreamReader(in));
                String read = null;
                while((read = br.readLine()) != null) {
                    System.out.println(read);
                }
            }
            System.out.println("--------------------POST END--------------------");
```

## 10. 最后别忘了在finally里关闭

```java
httpclient.close();
```

## 11. 附：

### 通过KeyStore获取证书

```java
Certificate certificate = ks.getCertificate("");
```

### 替换证书

```java
            //获取所有别名
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias != null && alias.startsWith("")) {
                    ks.deleteEntry(alias);  //替换证书
                }
            }
            ks.setCertificateEntry("", certificate);
            FileOutputStream fos = new FileOutputStream("");
            ks.store(fos, password.toCharArray());  //存入KeyStore文件
```

### 直接使用JDK提供的接口

```java
import java.net.URL;
import java.net.HttpURLConnection;

URL url = new URL("http://www.huawei.com/");
HttpURLConnection uc = (HttpURLConnection)url.openConnection();
BufferedReader br = new BufferedReader(new InputStreamReader(uc.getInputStream()));
String in = null;
while((in = br.readLine()) != null) {
System.out.println(in);
}
```

# 三、代码

```java
package com.huawei.web;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * 调用HttpClient发送HTTPS请求
 * @author l00250989
 */
public class HttpsRequestUtil {

    /**
     * 自定义信任所有证书的TrustManager
     */
    private final TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
    };

    private static void echo(String str) {
        System.out.println(str);
    }

    public static void main(String args[]) {

        CloseableHttpClient httpclient = null;
        try {
            //加载KeyStore
            String keyStoreFilePath = "";
            String password = "";
            echo(KeyStore.getDefaultType().toString());
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream fin = new FileInputStream(keyStoreFilePath);
            ks.load(fin, password.toCharArray());

            //获取证书
            Certificate certificate = ks.getCertificate("");
            //获取所有别名
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias != null && alias.startsWith("")) {
                    ks.deleteEntry(alias);  //替换证书
                }
            }
            ks.setCertificateEntry("", certificate);
            FileOutputStream fos = new FileOutputStream("");
            ks.store(fos, password.toCharArray());  //存入KeyStore文件

            //使用KeyStore初始化TrustManagerFactory
            echo(TrustManagerFactory.getDefaultAlgorithm().toString());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            //SSL上下文
            SSLContext sslcontext = SSLContext.getInstance("TLSv1.2");
            //sslcontext.init(null, trustAllCerts, null);
            sslcontext.init(null, tmf.getTrustManagers(), null);

            //SSLSocketFactory
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext);

            //创建请求客户端
            //httpclient = HttpClients.createDefault();
            httpclient = HttpClients.custom()
                    .setSSLSocketFactory(sslsf)  //自定义SSL工厂
                    .build();

            //创建GET方法
            HttpGet httpGet = new HttpGet("http://3ms.huawei.com/hi/home/index.html");

            //添加请求头
            httpGet.setHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) ...");

            //执行HTTP请求
            String responseBody = httpclient.execute(httpGet, response -> {
                //返回状态码
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    //返回实体
                    HttpEntity entity = response.getEntity();
                    return entity != null ? EntityUtils.toString(entity) : null;
                } else {
                    throw new ClientProtocolException("Unexpected response status: " + status);
                }
            });
            System.out.println(responseBody);
            System.out.println("--------------------GET END--------------------");

            //创建POST方法
            HttpPost httpPost = new HttpPost("http://talk.page.huawei.com");
            List<NameValuePair> nvps = new ArrayList<NameValuePair>();
            nvps.add(new BasicNameValuePair("username", "vip"));
            nvps.add(new BasicNameValuePair("password", "secret"));
            //创建请求实体
            httpPost.setEntity(new UrlEncodedFormEntity(nvps));
            //String parameter = "key=value";
            //httpPost.setEntity(new StringEntity(parameter, ContentType.create("application/x-www-form-urlencoded")));
            //执行HTTP请求
            CloseableHttpResponse response = httpclient.execute(httpPost);
            HttpEntity entity = response.getEntity();
            if(entity != null) {
                System.out.println(entity.getContentLength());
                InputStream in = entity.getContent();
                BufferedReader br = new BufferedReader(new InputStreamReader(in));
                String read = null;
                while((read = br.readLine()) != null) {
                    System.out.println(read);
                }
            }
            System.out.println("--------------------POST END--------------------");
        } catch (Exception e) {
            System.out.println(e);
        } finally {
            try {
                httpclient.close();
            } catch (IOException e) {
                System.out.println(e);
            }
        }
    }
}
```
