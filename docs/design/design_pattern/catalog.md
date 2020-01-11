# catalog

## 创建型

### 单例模式

[设计模式之单例模式](https://www.cnblogs.com/aaroncnblogs/p/8586892.html)

### 工厂模式

[设计模式之工厂模式](https://www.cnblogs.com/aaroncnblogs/p/8609161.html)

### 原型模式

实现Cloneable，重写Object.clone()调用super.clone()并修改为public

直接操作内存中的二进制流，适用于拷贝大对象

不能有final

浅拷贝（只复制基本数据类型，非数组，引用）

深拷贝（需要在clone()中调用引用的clone()）

## 结构型

### 适配器模式

#### 类

已存在A.a()

需要T.t()

创建

```java
AA extends A implement T
t() {
    super.a()
}
```

#### 对象

创建

```java
AA implement T
t() {
    // 通过构造方法传入实例, 或在接口实现中new
    new A.a()
}
```

适用于代码复用（和扩展），后期维护用，屏蔽了旧接口

### 装饰者模式

```java
New {
    Old o
    a() {
        // todo sth other
        o.a()
    }
}
```

比继承更灵活，适用于增加新功能（临时扩展），旧接口仍可用

### 代理模式

隐藏A接口

#### 静态代理

```java
P {
    R r
    m() {
        // todo
        r.m()
    }
}
```

#### 动态代理

反射

### 桥接

通过I1接口实现了C1和C2，通过I2接口实现C1'和C2'


## 行为型

### 观察者

```java
S {
    Vector<o>
    addo
    delo
    notifyo() {
        for V
        o.update()
    }
    dosth() {
        // todo
        notifyo()
    }
}
```
