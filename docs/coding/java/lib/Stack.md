# Stack

!!! abstract "Vector的子类: `class Stack<E> extends Vector<E>`"

```java
package libdemo;

import java.util.Stack;

public class StackDemo {

    public static void main(String args[]) {
        // 初始化
        Stack s = new Stack();
        System.out.println(s);

        // 压入栈
        s.push(1);
        System.out.println(s);
        s.push(2);
        System.out.println(s);
        s.push(3);
        System.out.println(s);

        // 弹出栈顶元素
        int i = (int) s.pop();
        System.out.println(i);
        System.out.println(s);

        // 查看栈顶元素
        int t = (int) s.peek();
        System.out.println(t);
        System.out.println(s);

        // 判空
        System.out.println(s.empty());
    }
}
```
