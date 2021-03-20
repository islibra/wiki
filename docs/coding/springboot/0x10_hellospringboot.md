# 0x10_hellospringboot

## 创建工程

http://start.spring.io/

> Project: Maven Project  
Language: Java  
Spring Boot: 2.1.7  
Group: com.example  
Artifact: demo  
Packaging: Jar  
Java: 8  
Dependencies: Spring Web Starter

## pom自动引入web依赖

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
                                      |-- ServletInitializer.java  // (Packaging选择War)
              |-- resources
                    |-- static
                    |-- templates
                          |-- xxx.html
                    |-- application.properties
                    |-- logback.xml
              |-- webapp (Packaging选择War)
                    |-- WEB-INF
                          |-- views
                                |-- index.jsp
        |-- test
              |-- java
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

## Maven构建

```
$ mvn clean package -DskipTests
```

## 启动主程序

```bash
$ java -jar demo-0.0.1-SNAPSHOT.jar
```

访问<http://127.0.0.1:8080/hello>返回`Hello World`

访问<http://127.0.0.1:8080/getUser>返回`{"username":"jack","password":"passW0rd"}`

## Web开发

### Thymeleaf

Spring Boot推荐使用[Thymeleaf](https://www.thymeleaf.org/)来代替JSP, HTML5模板引擎, 能直接在浏览器打开显示而不启动整个Web应用

对标产品: Velocity, FreeMaker

#### pom

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```

#### 实现上传文件

1. 在templates目录创建 **upload.html** 文件

    ```html
    <!DOCTYPE html>
    <html xmlns:th="http://www.thymeleaf.org">
        <body>

            <h1>Spring Boot file upload example</h1>

            <form method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" /><br/><br/>
                <input type="submit" value="Submit" />
            </form>

        </body>
    </html>
    ```

1. 在Controller中添加映射

    ```java
    @GetMapping("/")
    public String index() {
        // 映射到模板文件upload.html
        return "upload";
    }

    @PostMapping("/upload")
    public String fileUpload(@RequestParam("file") MultipartFile file,
        RedirectAttributes redirectAttributes) {

        // org.springframework.web.multipart.MultipartFile
        if (!file.isEmpty()) {
            byte[] bytes = file.getBytes();
            Path path = Paths.get("/tmp/" + file.getOriginalFilename());
            Files.write(path, bytes);
            // 也可以使用file.transferTo(new File(...))
        }

        redirectAttributes.addFlashAttribute("message", "File upload success!");

        // 302跳转到GET /uploadStatus请求
        return "redirect:/uploadStatus";
    }

    @GetMapping("/uploadStatus")
    public String uploadStatus() {
        return "uploadStatus";
    }
    ```

1. 在templates目录创建 **uploadStatus.html** 文件

    ```xml
    <!DOCTYPE html>
    <html lang="en" xmlns:th="http://www.thymeleaf.org">
        <body>

            <h1>Spring Boot - Upload Status</h1>

            <div th:if="${message}">
                <h2 th:text="${message}"/>
            </div>

        </body>
    </html>
    ```

1. 设置application.properties属性限制文件大小

    ```properties
    # 单个文件的最大值
    spring.servlet.multipart.max-file-size=10MB
    # 上传文件总的最大值
    spring.servlet.multipart.max-request-size=10MB
    ```

!!! quote "参考链接"
    - [Spring Boot(十七)：使用 Spring Boot 上传文件](http://www.ityouknow.com/springboot/2018/01/12/spring-boot-upload-file.html)
    - [Spring Boot教程(十三)：Spring Boot文件上传](https://blog.csdn.net/gnail_oug/article/details/80324120)

### JSP

创建工程时Packaging选择War

#### pom

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-tomcat</artifactId>
        <!-- 防止部署到外置Tomcat时出现冲突 -->
        <scope>provided</scope>
    </dependency>
    <!-- 导入jasper和jstl避免出现404 -->
    <dependency>
        <groupId>org.apache.tomcat.embed</groupId>
        <artifactId>tomcat-embed-jasper</artifactId>
    </dependency>
    <dependency>
        <groupId>javax.servlet</groupId>
        <artifactId>jstl</artifactId>
    </dependency>

    <!-- 防止修改JSP需重启 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-devtools</artifactId>
        <scope>runtime</scope>
        <optional>true</optional>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
        <exclusions>
            <exclusion>
                <groupId>org.junit.vintage</groupId>
                <artifactId>junit-vintage-engine</artifactId>
            </exclusion>
        </exclusions>
    </dependency>
</dependencies>
```

#### 自动初始化Servlet

```java
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

public class ServletInitializer extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(
            SpringApplicationBuilder application) {
        return application.sources(MvcdemoApplication.class);
    }
}
```

#### 在application.properties添加MVC映射

```properties
spring.mvc.view.prefix=/WEB-INF/views/
spring.mvc.view.suffix=.jsp

# 防止修改JSP需重启
# server.servlet.jsp.init-parameters.development=true
```

或application.yml

```yml
spring:
  mvc:
    view:
      prefix: /WEB-INF/views/
      suffix: .jsp
```

#### JSP页面

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
    Hello World!
</body>
</html>
```

#### 启动访问

1. 方式一: 启动MvcdemoApplication, 浏览器访问http://127.0.0.1:8080/
1. 方式二: Maven构建成war, 部署到外置Tomcat

!!! quote "参考链接: [SpringBoot 添加对JSP的支持（附常见坑点）](https://www.jianshu.com/p/de939365c472)"
