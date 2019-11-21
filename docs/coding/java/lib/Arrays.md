# Arrays

```java
import java.util.Arrays;

/**
 * java.util.Arrays: 对数组进行查找和排序的工具类
 */
public class ArraysDemo {

    public static void main(String args[]) {
        int[] ary = new int[]{9, 2, 5, 7, 4};

        // 二分查找
        System.out.println(Arrays.binarySearch(ary, 2));
        // 指定索引区间进行二分查找
        System.out.println(Arrays.binarySearch(ary, 1, 3, 2));

        // 拷贝数组, 超长截断
        int[] cp = Arrays.copyOf(ary, 2);
        System.out.println(Arrays.toString(cp));
        // 拷贝数组, 不足补0
        int[] cp2 = Arrays.copyOf(ary, 10);
        System.out.println(Arrays.toString(cp2));
        // 拷贝数组区间, 左闭右开
        int[] cp3 = Arrays.copyOfRange(ary, 1, 3);
        System.out.println(Arrays.toString(cp3));

        // 数组排序
        Arrays.sort(ary);
        System.out.println(Arrays.toString(ary));
    }
}
```
