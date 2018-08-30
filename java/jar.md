---
title: jar
date: 2018-08-25 20:25:28
categories: java
tags:
---

# Linux后台运行jar

```bash
java -jar XXX.jar  #当前ssh窗口被锁定；使用Ctrl + C打断程序运行；窗口关闭，程序退出。
java -jar XXX.jar &  #后台运行；窗口关闭，程序退出。
nohup java -jar XXX.jar &  #终端关闭，程序仍然运行。所有输出被重定向到nohup.out。
nohup java -jar XXX.jar >temp.txt &  #输出重定向。
jobs  #查看后台运行的任务，显示编号。
fg 23  #将编号指定任务调回到前台控制。
```


# 使用批处理或shell启动jar

1. 假设`${ROOT}`为项目根目录，已将工程打包成`${ROOT}\test.jar`
2. 拷贝jre到`${ROOT}\jre`
3. 拷贝依赖的库文件，到`${ROOT}\lib`
4. 在`${ROOT}`创建bat文件：

```bash
@echo off
start .\jre\bin\javaw.exe -jar .\test.jar
@pause
```

> 如果是java.exe，默认显示运行窗口；javaw.exe默认不显示。

或在`${ROOT}`创建sh文件：

```bash
chmod -R 740 *
CLASSPATH=$CLASSPATH:./lib/com.springsource.oracle.jdbc-11.1.0.7.jar
CLASSPATH=$CLASSPATH:./lib/com.springsource.org.apache.log4j-1.2.16.jar
CLASSPATH=$CLASSPATH:./lib/dom4j-1.6.1.jar
CLASSPATH=$CLASSPATH:./lib/com.springsource.org.apache.commons.lang-2.6.0.jar
CLASSPATH=$CLASSPATH:./lib/jsch-0.1.54.jar
CLASSPATH=$CLASSPATH:./lib/jtds-1.3.1.jar
CLASSPATH=$CLASSPATH:./DBSyncTool.jar
export classpath=$CLASSPATH
./jre/bin/java -Xms256m -Xmx1024m -classpath "$CLASSPATH" com.test.DBSync
``` 

> bat启动需要在工程打包的时候，将`classpath`路径写入jar中的`META-INF`中的`MANIFEST.MF`文件，否则会报找不到类。

## 1. ant编译：

```xml
<target name="jar.DBSyncTool" depends="copy.DBSyncTool.lib">
        <pathconvert property="mf.classpath" pathsep=" ">
            <path refid="classpath" />
            <chainedmapper>
                <flattenmapper />
                <globmapper from="*" to="lib/*" />
            </chainedmapper>
        </pathconvert>
        <jar destfile="../SecospacePackage/resource/moduler/tools/DBSyncTool/DBSyncTool.jar">
            <manifest>
                <attribute name="Main-Class" value="com.huawei.DBSync"/>
                <attribute name="Class-Path" value="${mf.classpath}"/>
            </manifest>
            <fileset dir="./target/classes" excludes="" />
        </jar>
</target>
 ```

## 2. maven编译：

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-jar-plugin</artifactId>
    <version>2.6</version>
    <configuration>
        <archive>
            <manifest>
                <addClasspath>true</addClasspath>
                <classpathPrefix>./lib/</classpathPrefix>
                <mainClass>com.test.MainClass</mainClass>
                <useUniqueVersions>false</useUniqueVersions>
            </manifest>
            <manifestEntries>
                <Class-Path>.</Class-Path>
            </manifestEntries>
        </archive>
        <excludes>
			<exclude>xxx.yaml</exclude>
		</excludes>
        <classesDirectory>
        </classesDirectory>
    </configuration>
</plugin>
 ```
