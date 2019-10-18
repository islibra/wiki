# SpringCloud

## Eureka微服务治理

- 注册
- 续约(心跳)
- 下线
- 剔除(未收到心跳)

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
</dependency>
```

### 核心注解

```java
@EnableEurekaServer
@SpringBootApplication
public class EurekaServerApplication
```

### API

> API源码位置: eureka-core-x.x.x.jar

API | 方式 | 说明
--- | --- | ---
/eureka/apps | GET | 查询所有注册的微服务
/eureka/apps/{appId} | GET | 查询指定微服务的所有信息，返回该微服务所有运行实例
/eureka/apps/{appId}/{instanceId} | GET | 查询指定微服务指定运行实例的信息
/eureka/instances/{instanceId} | GET | 按实例ID查询对应的实例
/eureka/apps/{appId}/{instanceId} | DELETE | 删除指定微服务的某个实例
/eureka/apps/{appId} | POST | 注册新的实例
/eureka/apps/{appId}/{instanceId}/status?value=OUT_OF_SERVICE | PUT | 暂停/下线应用实例
/eureka/apps/{appId}/{instanceId}/status?value=UP | PUT | 恢复应用实例
/eureka/apps/{appId}/{instanceId} | PUT | 应用实例发送心跳
/eureka/apps/{appId}/{instanceId}/metadata?version=1.1.1 | PUT | 修改应用实例元数据

## EurekaClient提供REST接口

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-eureka</artifactId>
</dependency>
```

### 核心注解

```java
@EnableEurekaClient
@SpringBootApplication
public class EurekaclientApplication
```

## Ribbon服务消费者

1. 同时作为EurekaClient提供负载均衡的REST接口
1. 接口调用Service方法
1. Service注入RestTemplate, 发送实际的REST请求
1. RestTemplate开启负载均衡

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-eureka</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-ribbon</artifactId>
</dependency>
```

### 核心注解

```java
@EnableDiscoveryClient  //向服务中心注册
@SpringBootApplication
public class RibbonApplication
```

## zuul路由网关

1. 同时作为EurekaClient提供REST接口
1. 可以使用过滤器ZuulFilter进行token校验

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-eureka</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-zuul</artifactId>
</dependency>
```

### 核心注解

```java
@EnableEurekaClient
@EnableZuulProxy
@SpringBootApplication
public class ZuulApplication
```

## Hystrix断路器

1. 同时作为EurekaClient提供REST接口
1. 在消费者service方法上添加注解指定熔断方法
    ```java
    @HystrixCommand(fallbackMethod="hiError")  //创建熔断功能并指定熔断方法
    ```

1. 在消费者service中添加熔断方法
    ```java
    public String hiError(String name) {  //熔断方法
        return "hi, " + name + ", sorry, error!";
    }
    ```

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-hystrix</artifactId>
</dependency>
```

### 核心注解

```java
@EnableDiscoveryClient
@EnableHystrix  //开启断路器
@SpringBootApplication
public class RibbonApplication
```

## Hystrix Dashboard

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-hystrix-dashboard</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

### 核心注解

```java
@EnableDiscoveryClient
@EnableHystrix
@EnableHystrixDashboard
@SpringBootApplication
public class RibbonApplication
```

## 配置中心

在application.properties中配置git仓地址, 分支, 路径, 用户名, 密码

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-config-server</artifactId>
</dependency>
```

### 核心注解

```java
@EnableConfigServer
@SpringBootApplication
public class ConfigserverApplication
```

## 配置中心Client

1. 在bootstrap.properties中配置label, profile, uri
1. 在Controller中通过`@Value("${foo}")`获取值

### 核心依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-config</artifactId>
</dependency>
```
