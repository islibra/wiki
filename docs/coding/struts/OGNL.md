# OGNL

Object Graphic Navigation Language

## 应用场景

1. 对象方法调用: `xxx.doSomething();`
1. 类静态方法/属性调用: `@[com.xxx.Class]@[field/method()]`, 如:
    - `@java.lang.String@format('foo %s', 'bar');`
    - `@tutorial.MyConstant@APP_NAME;`
1. 赋值操作和表达式串联, 如:`price=100, discount=0.8, calculatePrice()`
1. 访问OGNL上下文(OGNL context)和ActionContext
1. 创建/操作集合对象

## 上下文OgnlContext

- 依赖库: `ognl-3.0.19.jar`
- 包: `package ognl;`
- 类: `public class OgnlContext implements {==Map==}`


## 使用步骤

```java tab="OgnlDemo.java" hl_lines="11 30 32 40 45"
package com.xxx;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

public class OgnlDemo {

    public static void main(String[] args) {
        // 1. 创建一个Ognl上下文对象
        OgnlContext context = new OgnlContext();

        // 存放数据
        context.put("cn", "China");
        // 获取数据
        String value = (String)context.get("cn");
        System.out.println(value);

        // 存放对象
        User u = new User();
        u.setID(100);
        u.setName("Amanda");
        context.put("user", u);
        // 获取对象
        Object o = context.get("user");
        System.out.println(o);

        // 使用OGNL表达式获取对象属性, 如使用标签<s:a value="#user.ID">取值
        // 构建表达式
        Object exp = Ognl.parseExpression("#user.ID");
        // 解析表达式
        Object v = Ognl.getValue(exp, context, context.getRoot());
        System.out.println(v);

        // 获取根元素
        User u2 = new User();
        u2.setID(99);
        u2.setName("Bob");
        context.setRoot(u2);
        Object exp2 = Ognl.parseExpression("ID");
        Object v2 = Ognl.getValue(exp2, context, context.getRoot());
        System.out.println(v2);

        // 调用类静态方法, @[类全名(包括包路径)]@[方法名|属性名]
        Object exp3 = Ognl.parseExpression("@Math@floor(10.9)");
        Object v3 = Ognl.getValue(exp3, context, context.getRoot());
        System.out.println(v3);

        //Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc.exe')", context, context.getRoot());
        //Ognl.setValue(Runtime.getRuntime().exec("calc.exe"), context, context.getRoot());

        // 2. 创建ROOT对象
        Object rootObject = new Object();

        // 3. 解析表达式
        String exp = "(#nike='multipart/form-data').(#cmds={'calc.exe'}).(#p=new java.lang.ProcessBuilder(#cmds)).(#process=#p.start())";
        try{
            Object expression = ognl.Ognl.parseExpression(exp);

            // 4. 获取表达式的值, 取根元素不用#号, 取非根元素要使用#
            value = Ognl.getValue(expression, context, rootObject).toString();
        }catch (OgnlException e){
            e.printStackTrace();
        }
    }
}
```

```java tab="User.java"
package com.xxx;

public class User {

    int ID;
    String name;

    public int getID() {
        return ID;
    }

    public void setID(int ID) {
        this.ID = ID;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "User{" +
                "ID=" + ID +
                ", name='" + name + '\'' +
                '}';
    }
}
```


!!! quote "参考链接: [Ognl表达式基本原理和使用方法](https://www.cnblogs.com/cenyu/p/6233942.html)"
