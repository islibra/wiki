# aop

## 命名空间

```xml
<beans xmlns="http://www.springframework.org/schema/beans"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:p="http://www.springframework.org/schema/p"
    xmlns:aop="http://www.springframework.org/schema/aop"
    xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
    http://www.springframework.org/schema/aop
    http://www.springframework.org/schema/aop/spring-aop-3.0.xsd">
```

## 定义aspect

```java
public class Logging {

    public void beforeAdvice()
    {
        System.out.println("before cut.");
    }

    public void afterAdvice()
    {
        System.out.println("after cut.");
    }

    public void afterReturningAdvice(Object retVal)
    {
        System.out.println("return cut:" + retVal.toString());
    }

    public void afterThrowingAdvice(IllegalArgumentException ex)
    {
        System.out.println("exception cut:" + ex.getMessage());
    }
}
```

## 声明aspect, pointcut, advice

```xml
<bean id="logging" class="com.xxx.Logging"></bean>

<aop:config>
    <aop:aspect id="log" ref="logging">
        <aop:pointcut expression="execution(* com.xxx.News.getTitle(..))" id="selectAll"/>
        <aop:before method="beforeAdvice" pointcut-ref="selectAll" />
        <aop:after method="afterAdvice" pointcut-ref="selectAll" />
        <aop:after-returning method="afterReturningAdvice" returning="retVal" pointcut-ref="selectAll" />
        <aop:after-throwing method="afterThrowingAdvice" throwing="ex" pointcut-ref="selectAll" />
    </aop:aspect>
</aop:config>
```


## 通过注解定义AOP

```java
@Aspect
public class Logging {

   @Pointcut("execution(* com.xxx.*.*(..))")
   private void selectAll(){}

   @Before("selectAll()")
   public void beforeAdvice(){
   }
```

```xml
<aop:aspectj-autoproxy/>

<bean id="logging" class="com.xxx.Logging"/>
```
