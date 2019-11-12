# 0x01_select

## 选择排序

对于包含n个元素的列表

1. 每次遍历列表, 选出最大元素, 放入新的数组
1. 遍历n遍

时间复杂度: O(n^2^)

### 示例代码

```java
package sort;

import java.util.Enumeration;
import java.util.Vector;

public class SelectSort {

    public static Vector<Integer> sort(Vector<Integer> v) {
        Vector<Integer> result = new Vector<>();
        Integer max = Integer.MIN_VALUE;

        while (!v.isEmpty()) {
            System.out.println("size: " + v.size());
            Enumeration<Integer> e = v.elements();
            while (e.hasMoreElements()) {
                Integer i = e.nextElement();
                System.out.println("find: " + i + ", max: " + max);
                if (i > max) {
                    max = i;
                }
            }
            result.add(max);
            v.remove(max);
            max = Integer.MIN_VALUE;
        }
        return result;
    }

    public static void main(String args[]) {
        Vector<Integer> list = new Vector<>();
        list.add(5);
        list.add(3);
        list.add(6);
        list.add(2);
        list.add(10);
        System.out.println("origin: " + list);
        System.out.println("sorted: " + sort(list));
    }
}
```
