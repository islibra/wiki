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

```java tab="getValue"
package com.huawei;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

public class OgnlDemo {

    public static void main(String[] args) throws OgnlException {
        //创建一个Ognl上下文对象
        OgnlContext context = new OgnlContext();
        //@[类全名(包括包路径)]@[方法名|值名]
        Ognl.getValue("@java.lang.Runtime@getRuntime().exec('calc.exe')", context, context.getRoot());
    }
}
```

```java tab="setValue"
package com.huawei;

import ognl.Ognl;
import ognl.OgnlContext;
import ognl.OgnlException;

import java.io.IOException;

public class OgnlDemo {

    public static void main(String[] args) throws OgnlException, IOException {
        //创建一个Ognl上下文对象
        OgnlContext context = new OgnlContext();
        //@[类全名(包括包路径)]@[方法名|值名]
        Ognl.setValue(Runtime.getRuntime().exec("calc.exe"), context,context.getRoot());
    }
}
```

## 使用步骤

```java
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


!!! quote "参考链接: [Ognl表达式基本原理和使用方法](https://www.cnblogs.com/cenyu/p/6233942.html)"
