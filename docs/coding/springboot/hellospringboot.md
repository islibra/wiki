# hellospringboot

创建工程：<http://start.spring.io/>

> Project: Maven Project  
Language: Java  
Spring Boot: 2.1.7  
Group: com.example  
Artifact: demo  
Packaging: Jar  
Java: 8  
Dependencies: Spring Web Starter

??? note "pom自动引入web依赖"
    ```xml hl_lines="23 24"
    <?xml version="1.0" encoding="UTF-8"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    	<modelVersion>4.0.0</modelVersion>
    	<parent>
    		<groupId>org.springframework.boot</groupId>
    		<artifactId>spring-boot-starter-parent</artifactId>
    		<version>2.1.7.RELEASE</version>
    		<relativePath/> <!-- lookup parent from repository -->
    	</parent>
    	<groupId>com.example</groupId>
    	<artifactId>demo</artifactId>
    	<version>0.0.1-SNAPSHOT</version>
    	<name>demo</name>
    	<description>Demo project for Spring Boot</description>

    	<properties>
    		<java.version>1.8</java.version>
    	</properties>

    	<dependencies>
    		<dependency>
    			<groupId>org.springframework.boot</groupId>
    			<artifactId>spring-boot-starter-web</artifactId>
    		</dependency>

    		<dependency>
    			<groupId>org.springframework.boot</groupId>
    			<artifactId>spring-boot-starter-test</artifactId>
    			<scope>test</scope>
    		</dependency>
    	</dependencies>

    	<build>
    		<plugins>
    			<plugin>
    				<groupId>org.springframework.boot</groupId>
    				<artifactId>spring-boot-maven-plugin</artifactId>
    			</plugin>
    		</plugins>
    	</build>

    </project>
    ```

## 目录结构

```
demo
  |-- src
        |-- main
              |-- java
                    |-- com
                          |-- example
                                |-- demo
                                      |-- domain               // 实体和数据访问层
                                      |-- service              // 业务类代码
                                      |-- controller           // 页面访问控制
                                      |-- XxxApplication.java  // 应用入口
              |-- resources
                    |-- static
                    |-- templates
                          |-- application.properties
        |-- test
  |-- pom.xml
```

## 创建Domain

```java
package com.example.demo.domain;

public class User {
    String username;
    String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

## 创建Controller

```java
package com.example.demo.controller;

import com.example.demo.domain.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {
    @RequestMapping("/hello")
    public String index() {
        return "Hello World";
    }

    // 默认类中的方法都会以json格式返回
    @RequestMapping("/getUser")
    public User getUser() {
        User user = new User();
        user.setUsername("jack");
        user.setPassword("passW0rd");
        return user;
    }
}
```

Maven构建: `mvn clean package -DskipTests`

启动主程序:

```bash
$ java -jar demo-0.0.1-SNAPSHOT.jar

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::        (v2.1.7.RELEASE)

2019-08-29 14:16:47.982  INFO 4236 --- [           main] com.example.demo.DemoApplication         : Starting DemoApplication v0.0.1-SNAPSHOT on szxy8l002509891 with PID 4236 (F:\java\demo\target\demo-0.0.1-SNAPSHOT.jar started by l00250989 in F:\java\demo\target)
2019-08-29 14:16:47.982  INFO 4236 --- [           main] com.example.demo.DemoApplication         : No active profile set, falling back to default profiles: default
2019-08-29 14:16:50.998  INFO 4236 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat initialized with port(s): 8080 (http)
2019-08-29 14:16:51.091  INFO 4236 --- [           main] o.apache.catalina.core.StandardService   : Starting service [Tomcat]
2019-08-29 14:16:51.091  INFO 4236 --- [           main] org.apache.catalina.core.StandardEngine  : Starting Servlet engine: [Apache Tomcat/9.0.22]
2019-08-29 14:16:51.451  INFO 4236 --- [           main] o.a.c.c.C.[Tomcat].[localhost].[/]       : Initializing Spring embedded WebApplicationContext
2019-08-29 14:16:51.451  INFO 4236 --- [           main] o.s.web.context.ContextLoader            : Root WebApplicationContext: initialization completed in 3313 ms
2019-08-29 14:16:51.966  INFO 4236 --- [           main] o.s.s.concurrent.ThreadPoolTaskExecutor  : Initializing ExecutorService 'applicationTaskExecutor'
2019-08-29 14:16:52.419  INFO 4236 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  : Tomcat started on port(s): 8080 (http) with context path ''
2019-08-29 14:16:52.435  INFO 4236 --- [           main] com.example.demo.DemoApplication         : Started DemoApplication in 5.609 seconds (JVM running for 8.107)
```

访问<http://127.0.0.1:8080/hello>返回`Hello World`

访问<http://127.0.0.1:8080/getUser>返回`{"username":"jack","password":"passW0rd"}`
