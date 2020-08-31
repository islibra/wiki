# Lombok

<https://projectlombok.org/>

简化 POJO 中的 getter/setter/toString, 异常处理, I/O 流关闭

## 依赖

```xml
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.12</version>
    <scope>provided</scope>  <!-- 只在编译阶段生效 -->
</dependency>
```

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <version>3.8.0</version>
            <configuration>
                <source>1.8</source>
                <target>1.8</target>
                <annotationProcessorPaths>
                    <path>
                        <groupId>org.projectlombok</groupId>
                        <artifactId>lombok</artifactId>
                        <version>1.18.12</version>
                    </path>
                </annotationProcessorPaths>
            </configuration>
        </plugin>
    </plugins>
</build>
```

## IDE

- File - Settings - Plugins, 安装 Lombok
- File - Settings - Build, Execution, Deployment - Compiler, Enable annotation processing

## 使用

注解在类上对所有属性生效, 也可以单独注解在属性上

```java
@Getter
public class Word {
    private String value;

    private int count;

    public Word(String v, int c) {
        this.value = v;
        this.count = c;
    }
}
```
