# 定义

```java
public @interface DemoAnno {
}
```

# 使用

```java
@DemoAnno
public class TestAnno {
}
```

# 属性

> + 注解的属性也叫做成员变量。注解**只有成员变量**，没有方法。
> + 注解的成员变量在注解的定义中以**无形参的方法**形式来声明。
> + 方法名定义了该成员变量的名字。
> + 返回值定义了该成员变量的类型。

```java
public @interface DemoAnno {
    int id();
    String role() default "";
}

@DemoAnno(id = 0, role = "coder")
public class TestAnno {
}
```

# 元注解

* @Retention 生命周期
    * RetentionPolicy.SOURCE
    * RetentionPolicy.CLASS
    * RetentionPolicy.RUNTIME
* @Documented 包含到Javadoc
* @Target 注解位置
    * ElementType.ANNOTATION_TYPE 注解
    * ElementType.CONSTRUCTOR 构造方法
    * ElementType.FIELD 属性
    * ElementType.LOCAL_VARIABLE 局部变量
    * ElementType.METHOD 方法
    * ElementType.PACKAGE 包
    * ElementType.PARAMETER 参数
    * ElementType.TYPE 类、接口、枚举
* @Inherited 可以被继承
* @Repeatable 可重复应用

```java
public @interface DemoAnnoGroup {
    DemoAnno[] value();  //该注解存放其他注解的数组
}

@Repeatable(DemoAnnoGroup.class)  //该注解是可以被重复应用的
public @interface DemoAnno {
    String role() default "";
}

@DemoAnno(role = "coder")
@DemoAnno(role = "PM")
public class TestAnno {
}
```

# 预置的注解

* @Deprecated 已过时
* @Override 标明该方法是重写父类的方法
* @SuppressWarnings("deprecation") 屏蔽告警
* 函数式接口
```java
@FunctionalInterface
public interface Runnable {
    public abstract void run();
}
```

# 注解与反射

> **注意** 注解需要添加上`@Retention(RetentionPolicy.RUNTIME)`才能在运行时被读取到。

```java
        boolean hasAnno = TestAnno.class.isAnnotationPresent(DemoAnnoGroup.class);  //判断TestAnno类是否添加了DemoAnno注解

        if (hasAnno) {
            DemoAnnoGroup demoAnnoGroup = TestAnno.class.getAnnotation(DemoAnnoGroup.class);  //获取注解
            for (DemoAnno demoAnno : demoAnnoGroup.value()) {
                System.out.println(demoAnno.id());
                System.out.println(demoAnno.role());
            }
        }
        
        
        try {
            Field age = TestAnno.class.getDeclaredField("age");
            age.setAccessible(true);
            DemoAnno demoAnno = age.getAnnotation(DemoAnno.class);
            if (null != demoAnno)
            {
                System.out.println(demoAnno.id());
                System.out.println(demoAnno.role());
            }

            Method met = TestAnno.class.getDeclaredMethod("say");
            Annotation[] ans = met.getAnnotations();
            for (int i = 0; i < ans.length; i++)
            {
                System.out.println(ans[i].annotationType().getSimpleName());
            }
        } catch (NoSuchFieldException e) {
            System.out.println(e);
        } catch (NoSuchMethodException e) {
            System.out.println(e);
        }
```


# 典型应用

```java
            TestAnno ta = new TestAnno();
            Class clazz = ta.getClass();
            Method[] mets = clazz.getDeclaredMethods();
            for(Method m : mets)
            {
                if (m.isAnnotationPresent(DemoAnno.class))
                {
                    m.setAccessible(true);
                    m.invoke(ta, null);
                }
            }
```


参考原文：[https://blog.csdn.net/briblue/article/details/73824058](https://blog.csdn.net/briblue/article/details/73824058)
