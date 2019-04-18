---
title: Java读取properties配置文件
date: 2018-09-08 11:43:31
categories: java
tags:
---

# 读取类路径下的配置文件

配置文件路径：`src\main\resources\config\application.properties`

```java
private static final String PATH = "config/application.properties";
InputStream in = PropertiesUtil.class.getClassLoader().getResourceAsStream(PATH);
properties.load(in);
```


# 读取任意路径下的配置文件

```java
BufferedReader bufferedReader = new BufferedReader(new FileReader("F:/config.properties"));
properties.load(bufferedReader);
```


# 国际化

## 定义语言资源文件：

资源路径：`src\main\resources\localize\info.properties`

+ info_zh_CN.properties

```properties
username=\u7528\u6237\u540d
passwd=\u5BC6\u7801
input=\u8BF7\u8F93\u5165
info.success=\u6B22\u8FCE\uff0c{0}
info.error=\u767B\u5f55
```

> **Tips:** 在`IDEA - File - Settings - Editor - File Encodings`，设置`Global Encoding/Project Encoding/Properties Files - Default encoding for properties files`为 **UTF-8**，并勾选`Transparent native-to-ascii conversion`。

+ info_en_US.properties

## 创建本地语言环境对象：

```java
Locale locale = Locale.getDefault();  //获取默认的系统语言
if ("zh".equals(language))
{
    locale = new Locale("zh", "CN");
}
else if ("en".equals(language))
{
    locale = Locale.US;
}
System.out.println("language: " + locale.getLanguage() + ", country: " + locale.getCountry());
```

# 绑定资源文件

```java
ResourceBundle res = ResourceBundle.getBundle("localize.info", locale);
```

# 读取资源

```java
String input = res.getString("input");
String success = MessageFormat.format(res.getString(key), param);  //动态处理文本
```


# 代码

```java
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Properties;
import java.util.ResourceBundle;

public class PropertiesUtil {

    private static final String PATH = "config/application.properties";

    private static Properties properties;

    static
    {
        init();
    }

    private static Properties init()
    {
        properties = new Properties();

        InputStream in = null;
        try {
            //配置文件在类路径下
            in = PropertiesUtil.class.getClassLoader().getResourceAsStream(PATH);
            properties.load(in);
            //读取任意路径下的配置文件
            //BufferedReader bufferedReader = new BufferedReader(new FileReader("F:/config.properties"));
            //properties.load(bufferedReader);
        } catch (FileNotFoundException e) {
            System.out.println("Properties not exist.");
        } catch (IOException e) {
            System.out.println("Properties load error.");
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    System.out.println("Close inputStream fail.");
                }
            }
        }
        return properties;
    }

    public static String getValue(String key) {
        if (null == key) {
            return null;
        } else {
            return properties.getProperty(key);
        }
    }

    public static String getResValue(String key, String language, String param)
    {
        if (null == key) {
            return null;
        } else {
            Locale locale = Locale.getDefault();  //获取默认的系统语言

            if ("zh".equals(language))
            {
                locale = new Locale("zh", "CN");
            }
            else if ("en".equals(language))
            {
                locale = Locale.US;
            }
            System.out.println("language: " + locale.getLanguage() + ", country: " + locale.getCountry());

            ResourceBundle res = ResourceBundle.getBundle("localize.info", locale);

            if (null == param)
            {
                return res.getString(key);
            }
            return MessageFormat.format(res.getString(key), param);
        }
    }

    public static void main(String args[])
    {
        System.out.println(PropertiesUtil.getValue("exampleKey"));
        System.out.println(PropertiesUtil.getResValue("name", "en", null));
        System.out.println(PropertiesUtil.getResValue("msg", "zh", "hello"));
    }
}
```
