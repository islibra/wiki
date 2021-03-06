# 0xFF_注解

## Spring

### Configuration Bean

- org.springframework.context.annotation.**Configuration**: 表示这个类可以使用 Spring IoC 容器作为 Bean 定义的来源，相当于xml配置文件，所有带 @Bean 注解的方法返回的都是同一个实例。（使用 AnnotationConfigApplicationContext 来加载并把他们提供给 Spring 容器。）
    - org.springframework.stereotype.**Component** 的别名: 带 @Bean 注解的方法返回的都是新的实例。

- org.springframework.context.annotation.**Bean**: 可理解为用Spring的时候xml里面的bean标签，方法将返回一个对象，方法名称作为 bean 的 id，如：

```java
@Configuration
public class BeanConfig {
    @Bean
    public News news()
    {
        return new News();
    }
}
```

相当于：

```xml
<bean id="news" class="com.xxx.News">
</bean>
```


## Spring Boot

### SpringBootApplication

- org.springframework.boot.autoconfigure.**SpringBootApplication**
    - org.springframework.context.annotation.**ComponentScan** 的别名: 指明对象扫描范围，默认只扫描当前启动类所在的包里的对象
        - basePackages = {"com.xxx.yyy"}
        - basePackageClasses = 要扫描类.class所在位置的包

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

### RestController RequestMapping

- org.springframework.web.bind.annotation.**RestController**: 注解在Controller类上, 提供RESTful接口
    - org.springframework.stereotype.**Controller** 的别名
        - org.springframework.stereotype.**Component** 的别名

- org.springframework.web.bind.annotation.**PostMapping**
- org.springframework.web.bind.annotation.**GetMapping**
    - org.springframework.web.bind.annotation.**RequestMapping** 的别名: 注解在方法上, 提供URL映射

```java
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
public class UploadController {
    @RequestMapping("/upload")
    public String index() {
        return "upload";
    }
}
```

### RequestParam

- org.springframework.web.bind.annotation.**RequestParam**, 请求参数

```java
@PostMapping("/upload")
public String fileUpload(@RequestParam("file") MultipartFile file,
    RedirectAttributes redirectAttributes) {
    return "redirect:/uploadStatus";
}
```


## Pattern Valid - 表单校验

1. 增加正则表达式

    ```java hl_lines="3 7"
    package com.example.demo.domain;

    import javax.validation.constraints.Pattern;

    public class User {

        @Pattern(regexp="[^0-9]*")
        String username;
    }
    ```

1. Controller增加校验

    ```java hl_lines="2"
    @RequestMapping(value = "/addEmployee", method = RequestMethod.POST)
    public String submit(@Valid @ModelAttribute("employee") Employee employee) {
        // Code that uses the employee object
        return "employeeView";
    }
    ```


!!! quote "参考链接: [Form Validation – part 4 (using annotation @Pattern, @Past, @Max etc)](http://technicalstack.com/form-validation-part-4-using-annotation-pattern-past-max-etc/)"

---

- @import: 从另一个配置类中加载 @Bean 定义。
- @ConditionalOnProperty(name = "synchronize", havingValue = "true"): 控制Configuration是否生效，name为application.properties中配置的属性。
- @Value: 值注入
    - 外部注入：
        - 普通字符串`@Value("normal")`
        - 操作系统属性`@Value("#{systemProperties['os.name']}")`
        - 表达式结果`@Value("#{ T(java.lang.Math).random() * 100.0 }")`
        - 其他bean属性`@Value("#{beanInject.another}")`
        - 文件资源`@Value("classpath:com/hry/spring/configinject/config.txt")`
        - URL资源`@Value("http://www.baidu.com")`
    - 配置文件注入：`@Value("${app.name}")`
- @PropertySource({"classpath:com/xxx/config.properties", "classpath:com/yyy/config_${anotherfile.configinject}.properties"}) 引入外部配置文件组，${anotherfile.configinject}的值来自于第一个配置文件，相同的key最后一个生效。

!!! example "示例代码"
    ```java
    @Configuration
    @Import(ConfigA.class)
    public class BeanConfig {
      //指定实例名称和初始化方法
      @Bean(name="news", initMethod = "init", destroyMethod = "cleanup")
      //默认是单例模式，即scope="singleton"。另外scope还有prototype、request、session、global session作用域。scope="prototype"多例
      @Scope("prototype")
      public News news()
      {
        return new News();
      }
    }
    ```


## @ModelAttribute

将方法参数或返回值与model属性绑定，从而在view用使用。

### 使用方法

#### 1. 注解在方法上

在@RequestMapping之前被调用。

!!! example "注解在方法上"
    ```java
    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("msg", "Welcome to the Netherlands!");
    }
    ```

#### 2. 注解在方法参数上

在调用方法之前，将请求中的参数与model属性绑定。

!!! example "注解在方法参数上"
    ```java
    @RequestMapping(value = "/addEmployee", method = RequestMethod.POST)
    public String submit(@ModelAttribute("employee") Employee employee) {
        // Code that uses the employee object
        return "employeeView";
    }
    ```

#### 代码示例

```html tab="view"
<form:form method="POST" action="/spring-mvc-java/addEmployee"
  modelAttribute="employee"><!--绑定了model名称，在表单请求中，参数只要写属性名称就可以了-->
    <form:label path="name">Name</form:label>
    <form:input path="name" />

    <form:label path="id">Id</form:label>
    <form:input path="id" />

    <input type="submit" value="Submit" />
</form:form>
```

```java tab="controller"
@Controller
@ControllerAdvice
public class EmployeeController {

    private Map<Long, Employee> employeeMap = new HashMap<>();

    @RequestMapping(value = "/addEmployee", method = RequestMethod.POST)
    public String submit(
      @ModelAttribute("employee") Employee employee,
      BindingResult result, ModelMap model) { //与表单中的名称一致
        if (result.hasErrors()) {
            return "error";
        }
        model.addAttribute("name", employee.getName());
        model.addAttribute("id", employee.getId());

        employeeMap.put(employee.getId(), employee);

        return "employeeView"; //返回JSP
    }

    //在调用submit之前实例化model
    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("msg", "Welcome to the Netherlands!");
    }
}
```

```java tab="model"
@XmlRootElement
public class Employee {

    private long id;
    private String name;

    public Employee(long id, String name) {
        this.id = id;
        this.name = name;
    }

    // standard getters and setters removed
}
```

```html tab="result"
<h3>${msg}</h3>
Name : ${name}
ID : ${id}
```

!!! quote "参考链接"
    <https://www.baeldung.com/spring-mvc-and-the-modelattribute-annotation>
