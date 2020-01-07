# 0x00_hellospring

## xml

```xml
<bean id="news" class="com.xxx.News"
    init-method="init" destroy-method="destroy">
    <property name="title" value="Hello World!"/>
</bean>
```

## context

```java
AbstractApplicationContext context = new ClassPathXmlApplicationContext("Beans.xml");
News objA = (News)context.getBean("news");
System.out.println(objA.getTitle());
```

## IOC

### 构造函数

```xml
<bean id="textEditor" class="com.tutorialspoint.TextEditor">
    <constructor-arg ref="spellChecker"/>
</bean>

<bean id="spellChecker" class="com.tutorialspoint.SpellChecker">
</bean>
```

### 属性

```xml
<bean id="textEditor" class="com.tutorialspoint.TextEditor">
    <property name="spellChecker" ref="spellChecker"/>
</bean>

<bean id="spellChecker" class="com.tutorialspoint.SpellChecker">
</bean>
```

## 注解

```java tab="定义"
@Configuration
public class BeanConfig {
    @Bean(initMethod = "init", destroyMethod = "cleanup")
    @Scope("prototype")
    public News news()
    {
        return new News();
    }
}
```

```java tab="调用"
ApplicationContext ctx = new AnnotationConfigApplicationContext(BeanConfig.class);
News obj = ctx.getBean(News.class);
obj.setTitle("BeanConfig World!");
System.out.println(obj.getTitle());
```

## JDBC

## MVC
