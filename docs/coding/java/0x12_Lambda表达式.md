# 0x12_Lambda表达式

!!! tip "Lamda 表达式可以替换为匿名类"

Lambda表达式表示函数接口的实例，可以作为参数传递进方法中。


# 语法

> (parameters) -> expression

或

> (parameters) -> { statements; }


## 可选类型声明

> (int a, int b) -> a + b;
> (a, b) -> a - b;


## 可选圆括号

> (message) -> System.out.println(message);
> message -> System.out.println(message);  //一个参数无需圆括号，多个参数需要圆括号


## 可选大括号

> (a, b) -> { return a * b; };
> (a, b) -> return a * b;  //只有一个语句，不需要使用大括号


## 可选返回关键字

> (a, b) -> return a / b;
> (a, b) -> a / b;  //只有一个表达式返回值


# 典型应用

```java
public class LambdaTest {

    public static void main(String[] args) {
        int factor = 3;
        MyIntCalc calc = i -> i * factor;  //2、Lambda表达式。可以引用局部变量但不可改变局部变量，可以改变非局部变量。
        System.out.println(calc.calcInt(4));  //3、接口执行
    }

}

interface MyIntCalc {  //1、函数式接口
    public Integer calcInt(Integer i);
}
```


## 作为函数参数传入

```java
public class LambdaTest {

    public static void main(String[] args) {
        engine((x, y) -> x + y);  //3、Lambda表达式及函数调用
        engine((x, y) -> x - y);
    }

    private static void engine(MyLongCalc calc) {  //2、接收函数式接口作为参数的函数
        long x = 3L, y = 2L;
        System.out.println(calc.calcLong(x, y));
    }
}

interface MyLongCalc {  //1、函数式接口
    public Long calcLong(Long x, Long y);
}
```


## 作为返回值

```java
public class LambdaTest {

    public static void main(String[] args) {
        System.out.println(getAlgorithm().calcLong(1L, 2L));  //3、函数调用
    }

private static MyLongCalc getAlgorithm() {  //2、返回类型为函数式接口的函数及Lambda表达式
        return (x, y) -> x + y;
    }
}

interface MyLongCalc {  //1、函数式接口
    public Long calcLong(Long x, Long y);
}
```


# Java内置的函数式接口

```java
import java.util.function.Function;

public class LambdaTest {

    public static void main(String[] args) {
        Function<String, Integer> func = str -> str.length();  //接收T，返回R
        System.out.println(func.apply("This is a function."));
    }
}
```

```java
public interface BiFunction<T,U,R>{
   public R apply(T t, U u);  //接收T和U，返回R
}

public Predicate<T> {
   public boolean test(T  t);  //返回布尔
}

public interface BiPredicate<T,U>{
   public boolean test(T t, U u);  //接收两个参数并返回布尔
}

public interface Consumer<T>{
   public void accept(T t);  //返回void
}

public interface BiConsumer<T,U>{
   public void accept(T t, U  u);  //接收两个参数并返回void
}

public interface Supplier<T>{
    public T get();  //无参并返回T
}

public interface UnaryOperator<T>{
   public T  apply(T t);  //接收T并返回T
}

public interface BinaryOperator<T>{
   public T apply(T t1, T t2);  //接收两个T并返回T
}
```

以上是通用版本，IntConsumer 是 Consumer<T> 的专用版本。


# 交叉类型

使Lambda表达式，即函数式接口的实例可序列化，如：

```java
java.io.Serializable ser = (java.io.Serializable & MyLongCalc) (x,y)-> x + y;
```


# 无参调用

```java
new Thread(() -> {System.out.println("hello");}).start();
```
