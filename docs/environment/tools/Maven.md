# Maven

!!! quote "官方网站: [Apache Maven Project](https://maven.apache.org/)"

> 前置条件: 已安装JDK，并设置环境变量`JAVA_HOME`和`path`。

## 设置环境变量

- M2_HOME=D:\opt\installer\apache-maven-3.6.3
- M2=%M2_HOME%\bin, 添加到path中
- MAVEN_OPTS=-Xms256m -Xmx512m

查看版本: `mvn -v`

## 配置文件

配置文件路径：`/conf/setting.xml`

```xml
  <!--本地仓路径-->
  <localRepository>D:\opt\installer\apache-maven-3.6.3\repo</localRepository>

  <!--为Maven配置代理访问网络-->
  <proxies>
    <proxy>
      <id>myproxy</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>proxy.somewhere.com</host>
      <port>8080</port>
      <username>proxyuser</username>
      <password>somepassword</password>
      <nonProxyHosts>*.google.com|ibiblio.org</nonProxyHosts>
    </proxy>
  </proxies>

  <!--从远程仓下载使用的镜像-->
  <mirrors>
    <mirror>
      <id>mirrorId</id>
      <name>Remote Mirror</name>
      <!--需镜像的远程仓，如*代表所有, central代表https://repo.maven.apache.org/maven2/-->
      <mirrorOf>central</mirrorOf>
      <url>http://downloads.planetmirror.com/pub/maven2</url>
    </mirror>
  </mirrors>

  <!--
  构建过程中的自定义配置，可以通过多种方式激活, 如:
  1. <activatedProfiles>标签
  2. 系统属性, 如JDK版本前缀
  3. cmd指定
  -->
  <profiles>
    <profile>
      <id>test</id>

      <activation>
        <activeByDefault>false</activeByDefault>

        <!--在JDK 1.8版本构建时被激活-->
        <jdk>1.8</jdk>

        <!--在系统属性mavenVersion的值为2.0.3时被激活-->
        <property>
          <name>mavenVersion</name>
          <value>2.0.3</value>
        </property>
      </activation>

      <!--定义变量, 当该profile被激活时，在pom.xml中通过${user.install}访问该属性-->
      <properties>
        <user.install>/path/to/our-project</user.install>
      </properties>

      <!--定义Maven下载依赖和插件的远端仓库地址-->
      <repositories>
        <repository>
          <id>codehausSnapshots</id>
          <name>Codehaus Snapshots</name>
          <releases>
            <enabled>false</enabled>
            <updatePolicy>always</updatePolicy>
            <checksumPolicy>warn</checksumPolicy>
          </releases>
          <snapshots>
            <enabled>true</enabled>
            <updatePolicy>never</updatePolicy>
            <checksumPolicy>fail</checksumPolicy>
          </snapshots>
          <url>http://snapshots.maven.codehaus.org/maven2</url>
          <layout>default</layout>
        </repository>
      </repositories>
      <pluginRepositories>
        <!--...-->
      </pluginRepositories>
    </profile>
  </profiles>

  <!--在所有构建都激活的profile-->
  <activeProfiles>
    <activeProfile>env-test</activeProfile>
  </activeProfiles>
```


## 创建Maven工程

典型目录结构

- /src
    - /main
        - /java  **--源码**
        - /resources  **--资源文件**

    - /test
        - /java  **--测试代码**

- /target  **--编译生成的二进制文件**
    - /classes
    - xxx.jar  **--部署使用的jar**

- /pom.xml


## POM

```xml
<groupId>com.xxx</groupId>
<artifactId>yyy-demo</artifactId>
<version>1.0-SNAPSHOT</version>
<!-- 构建生成的文件类型 -->
<packaging>jar</packaging>
```

### 依赖管理

```xml
<dependencies>
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>fastjson</artifactId>
        <version>1.2.61</version>
    </dependency>
</dependencies>
```

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

### 插件管理

#### [Apache Maven JAR Plugin](http://maven.apache.org/plugins/maven-jar-plugin/)

构建jar

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-jar-plugin</artifactId>
            <version>3.2.0</version>
            <configuration>
                <archive>
                    <manifest>
                        <!-- 在MANIFEST.MF中添加Class-Path -->
                        <addClasspath>true</addClasspath>
                        <classpathPrefix>lib/</classpathPrefix>
                        <!-- 构建的jar中包含主类 -->
                        <mainClass>com.xxx.yyydemo.MainClass</mainClass>
                    </manifest>
                </archive>
            </configuration>
        </plugin>
    </plugins>
</build>
```

#### [Apache Maven Assembly Plugin](http://maven.apache.org/plugins/maven-assembly-plugin/)

构建时集成依赖, 该插件会将依赖jar解压, 包含到jar中

```xml
<plugin>
    <!-- NOTE: We don't need a groupId specification because the group is
         org.apache.maven.plugins ...which is assumed by default.
     -->
    <artifactId>maven-assembly-plugin</artifactId>
    <version>3.2.0</version>
    <configuration>
        <archive>
            <manifest>
                <mainClass>com.huawei.osidemo.ICAgent</mainClass>
            </manifest>
        </archive>
        <descriptorRefs>
            <descriptorRef>jar-with-dependencies</descriptorRef>
        </descriptorRefs>
    </configuration>
    <!-- 绑定到package生命周期上 -->
    <executions>
        <execution>
            <id>make-assembly</id>
            <phase>package</phase>
            <goals>
                <goal>single</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

#### [Apache Maven Dependency Plugin](https://maven.apache.org/plugins/maven-dependency-plugin/)

构建时包含依赖

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-dependency-plugin</artifactId>
    <version>3.1.2</version>
    <executions>
        <execution>
            <id>copy-dependencies</id>
            <phase>package</phase>
            <goals>
                <goal>copy-dependencies</goal>
            </goals>
            <configuration>
                <outputDirectory>target/lib</outputDirectory>
                <overWriteReleases>false</overWriteReleases>
                <overWriteSnapshots>false</overWriteSnapshots>
                <overWriteIfNewer>true</overWriteIfNewer>
                <excludeTransitive>false</excludeTransitive>
                <!-- Warning: 不要加这个, MANIFEST.MF会携带版本号, 如果不一致会导致找不到依赖
                <stripVersion>true</stripVersion>-->
            </configuration>
        </execution>
    </executions>
</plugin>
```


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

## 生命周期

- pre-clean -> clean -> post-clean
- validate -> initialize -> compile -> test -> package -> install -> depoly
- pre-site -> site -> post-site -> site-depoly

## 常用命令

```bash
mvn clean package/install -DskipTests
```


参考：[Maven 中 dependencies 与 dependencyManagement 的区别](https://zhuanlan.zhihu.com/p/31020263)
