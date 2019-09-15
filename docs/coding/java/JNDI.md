# JNDI

JNDI名字和目录API，用来存储和检索任何类型的java对象。

## 包

- javax.naming: JNDI API核心包，包含Context接口，InitalContext核心类，Reference
- javax.naming.directory: 目录补充包
- javax.naming.spi: 对接LDAP，RMI，DNS，CORBA，包含InitialContextFactory，ObjectFactory接口和NamingManager类

## tomcat指定工厂javaURLContextFactory

tomcat配置数据源三种方式：

- server.xml
- context.xml
- conf/Catalina/servername/appname.xml

```xml
<Resource
name="jdbc/example"
auth="Container"
type="javax.sql.DataSource"
maxActive="100"
maxIdle="30"
maxWait="10000"
username="root"
password="root"
driverClassName="com.mysql.jc.jdbc.Driver"
url="jdbc:mysql://localhost:3306/test?useUnicode=true&amp;characterEncoding=utf-8&amp;serverTimezone=UTC"/>
```

在web.xml中配置resource-ref后，代码中通过InitialContext.lookup获取DataSource类
