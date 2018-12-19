# 前置条件

已安装JDK，并设置环境变量`JAVA_HOME`和`path`。

# 设置环境变量

> M2_HOME=D:\software\apache-maven-3.3.3
> M2=%M2_HOME%\bin  **--添加到path中去**
> MAVEN_OPTS=-Xms256m -Xmx512m

# maven工程典型目录结构

> /src/main/java  **--源码**
> /src/main/resources  **--资源文件**
> /src/test  **--测试代码**
> /target  **--编译生成的二进制文件**
> /target/classes  **--部署使用的jar**
> /pom.xml

# POM

```xml
<groupId>com.aaron</groupId>
<artifactId>springBootDemo</artifactId>
<version>0.0.1-SNAPSHOT</version>
<packaging>jar</packaging>
```

## 依赖管理

在parent中配置dependencyManagement，统一管理jar版本。

```xml
<properties>
    <version.framework>1.0-SNAPSHOT</version.framework>
    <javaee-api.version>1.0-SNAPSHOT</javaee-api.version>
</properties>
<dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.zhisheng</groupId>
        <artifactId>framework-cache</artifactId>
        <version>${version.framework}</version>
      </dependency>
      <dependency>  
        <groupId>javax</groupId>  
        <artifactId>javaee-api</artifactId>  
        <version>${javaee-api.version}</version>  
      </dependency>  
    </dependencies>
</dependencyManagement>
```

子项目中引用依赖无需显示的列出版本号，继承父项目。

```xml
<parent>  
    <artifactId>parent</artifactId>  
    <groupId>com.zhisheng</groupId>
    <version>0.0.1-SNAPSHOT</version>  
	<relativePath>../parent/pom.xml</relativePath> 
</parent>
<!--依赖关系-->  
<dependencies>  
    <dependency>  
        <groupId>javax</groupId>  
        <artifactId>javaee-api</artifactId>  
        <!--此处若声明<version>将覆盖parent版本号-->  
    </dependency>  
    <dependency>
        <groupId>com.zhisheng</groupId>
        <artifactId>framework-cache</artifactId>
    </dependency>
    <dependency>  
        <groupId>com.fasterxml.jackson.core</groupId>  
        <artifactId>jackson-annotations</artifactId>  
    </dependency>  
</dependencies>
```

使用专门的POM来进行依赖管理。

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.zhisheng.sample</groupId>
  <artifactId>sample-dependency-infrastructure</artifactId>
  <packaging>pom</packaging>
  <version>1.0-SNAPSHOT</version>
  <dependencyManagement>
    <dependencies>
        <dependency>
          <groupId>junit</groupId>
          <artifactid>junit</artifactId>
          <version>4.8.2</version>
          <scope>test</scope>
        </dependency>
        <dependency>
          <groupId>log4j</groupId>
          <artifactid>log4j</artifactId>
          <version>1.2.16</version>
        </dependency>
    </dependencies>
  </dependencyManagement>
</project>
```

通过import scope方式引入依赖管理，不继承父项目。

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
          <groupId>com.zhisheng.sample</groupId>
          <artifactid>sample-dependency-infrastructure</artifactId>
          <version>1.0-SNAPSHOT</version>
          <type>pom</type>
          <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
<dependency>
    <groupId>junit</groupId>
    <artifactid>junit</artifactId>
</dependency>
<dependency>
    <groupId>log4j</groupId>
    <artifactid>log4j</artifactId>
</dependency>
```

## 插件管理

在parent中统一配置pluginManagement，与dependencyManagement类似，子项目继承父项目配置。

```xml
<build>
  <pluginManagement>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>2.5.1</version>
        <configuration>
          <source>1.8</source>
          <target>1.8</target>
          <encoding>UTF-8</encoding>
        </configuration>
      </plugin>
    </plugins>
  </pluginManagement>
</build>
```

# 生命周期

- pre-clean -> clean -> post-clean
- validate -> initialize -> compile -> test -> package -> install -> depoly
- pre-site -> site -> post-site -> site-depoly

# 仓库

配置文件路径：`/conf/setting.xml`

1. 本地：`<localRepository>D:\software\apache-maven-3.3.3\repo</localRepository>`
1. 中央：网络访问，无需配置
1. 远程


参考：[Maven 中 dependencies 与 dependencyManagement 的区别](https://zhuanlan.zhihu.com/p/31020263)
