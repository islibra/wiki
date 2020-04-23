# fastjson

提供Java对象和JSON字符串互相转换的Java库

- [官方网站](https://github.com/alibaba/fastjson)
- [新手指南](https://github.com/alibaba/fastjson/wiki/Quick-Start-CN)

## 添加依赖

```xml
<dependencies>
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>1.2.61</version>
    </dependency>
</dependencies>
```

## 使用

```java
package com.xxx.bean;

import java.util.List;

public class LogConfig {
    private String application;
    private List<String> fileList;

    // 注意必须要有无参构造方法, 否则反序列化失败
    public LogConfig() {
    }

    public LogConfig(String app, List<String> files) {
        this.application = app;
        this.fileList = files;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }

    public List<String> getFileList() {
        return fileList;
    }

    public void setFileList(List<String> fileList) {
        this.fileList = fileList;
    }
}
```

```java
package com.xxx.util;

import com.xxx.bean.LogConfig;

import com.alibaba.fastjson.JSON;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class JsonUtil {
    private static final Logger LOG = Logger.getLogger(JsonUtil.class.getName());

    public static void main(String[] args) {
        List<String> fileList = new ArrayList<String>();
        fileList.add("/var/log/app.log");
        LogConfig logConfig = new LogConfig("MyApp", fileList);
        // 序列化
        String logConfigJson = JSON.toJSONString(logConfig);
        // {"application":"MyApp","fileList":["/var/log/app.log"]}
        LOG.info(logConfigJson);

        String anotherJson = "{\"application\":\"AnotherApp\","
                + "\"fileList\":[\"/var/log/app.log\"]}";
        // 反序列化
        LogConfig anotherConfig = JSON.parseObject(anotherJson, LogConfig.class);
        // AnotherApp
        LOG.info(anotherConfig.getApplication());

        String arrayJson = "['北京','上海','深圳']";
        List<String> citys = JSON.parseArray(arrayJson, String.class);
        // [北京, 上海, 深圳]
        LOG.info(citys.toString());
    }
}
```
