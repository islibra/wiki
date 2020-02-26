# Restlet

!!! abstract "Restlet Framework: 用来创建RESTful API的Java开源框架"

!!! quote "官方网站: <https://restlet.talend.com/>"
    最新版本: 2.4.2, 2019-11-13

### POM

```xml
<repositories>
  <repository>
    <id>maven-restlet</id>
    <name>Restlet repository</name>
    <url>https://maven.restlet.talend.com</url>
  </repository>
</repositories>

<properties>
  <restlet-version>2.4.2</restlet-version>
</properties>

<dependencies>
  <dependency>
    <groupId>org.restlet.jse</groupId>
    <artifactId>org.restlet</artifactId>
    <version>${restlet-version}</version>
  </dependency>
  <dependency>
    <groupId>org.restlet.jse</groupId>
    <artifactId>org.restlet.ext.jackson</artifactId>
    <version>${restlet-version}</version>
  </dependency>
</dependencies>
```
