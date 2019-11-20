# Vector

动态数组: 数组大小可变

!!! example "与ArrayList的区别"
    1. Vector是同步访问的, {==线程安全==}  
    1. 有比集合更多的方法

```java
package libdemo;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Vector;

public class VectorDemo {

    public static void main(String args[]) {
        // 默认容量为10
        Vector v1 = new Vector();
        System.out.println(v1.size());
        System.out.println(v1.capacity());
        // 判断是否为空
        System.out.println(v1.isEmpty());

        // 指定初始容量为5
        Vector v2 = new Vector(5);
        System.out.println(v2.size());
        System.out.println(v2.capacity());

        // 指定初始容量为3, 增量为4
        Vector v3 = new Vector(3, 4);
        System.out.println(v3.size());
        System.out.println(v3.capacity());
        v3.add(0);
        v3.addElement(1);
        v3.add(2);
        // 超过当前容量时自动扩容
        v3.add(3);
        System.out.println(v3.size());
        System.out.println(v3.capacity());

        // 获取元素
        System.out.println(v3.firstElement());
        System.out.println(v3.lastElement());

        // 判断元素是否存在
        if (v3.contains(2)) {
            System.out.println("v3 contains 2, and index is " + v3.indexOf(2));
        }

        // 返回指定索引的元素
        System.out.println(v3.elementAt(1));
        System.out.println(v3.get(1));

        // 遍历元素
        Enumeration e = v3.elements();
        while (e.hasMoreElements()) {
            System.out.print(e.nextElement() + " ");
        }
        System.out.println();

        // 在指定位置增加元素
        v3.add(1, 9);
        v3.insertElementAt(8, 2);
        // 重新赋值
        v3.set(3, 7);
        System.out.println(v3);

        // 转换为数组
        Object[] nums = v3.toArray();
        System.out.println(Arrays.toString(nums));

        // 数组转向量
        Integer[] nums2 = {6, 7, 8, 9, 0};
        Vector<Integer> v4 = new Vector<Integer>(Arrays.asList(nums2));
        System.out.println(v4);
    }
}
```
