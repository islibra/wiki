# 0x00_binary_search

!!! abstract "典型应用: 在{==有序==}的{==数组(随机访问)==}中查找"

时间复杂度: O(log~2~n)


## 代码示例

```java tab="Java" hl_lines="16 17 21"
package search;

import java.util.Scanner;

public class BinarySearch {

    /**
     * 二分查找
     *
     * @param sortedList 有序数组
     * @param search     待查找元素
     * @return 若找到, 返回元素索引, 未找到, 返回-1
     */
    public int binarySearch(int[] sortedList, int search) {
        // 标记查找范围
        int low = 0;
        int high = sortedList.length - 1;

        while (low <= high) {
            // 每次查找中间元素
            int mid = (low + high) / 2;
            if (sortedList[mid] == search) {
                return mid;
            } else if (sortedList[mid] < search) {
                low = mid + 1;
            } else if (sortedList[mid] > search) {
                high = mid - 1;
            }
        }
        return -1;
    }

    public static void main(String args[]) {
        Scanner cin = new Scanner(System.in, "utf-8");

        String[] sortedListStr = cin.nextLine().split(",");
        int len = sortedListStr.length;
        int[] sortedList = new int[len];
        for (int i = 0; i < len; i++) {
            sortedList[i] = Integer.parseInt(sortedListStr[i]);
        }

        String searchStr = cin.nextLine();
        int search = Integer.parseInt(searchStr);

        BinarySearch bs = new BinarySearch();
        System.out.println(bs.binarySearch(sortedList, search));
    }
}
```

```python tab="Python"
# 伪代码
low=0, high=len-1
mid=(low+high)//2
if list[mid]<item
low=mid+1
```

## LeetCode

```java tab="35. 搜索插入位置"
import java.util.Scanner;

/**
 * 35. 搜索插入位置
 *
 * 给定一个排序数组和一个目标值，在数组中找到目标值，并返回其索引。
 * 如果目标值不存在于数组中，返回它将会被按顺序插入的位置。
 *
 * 你可以假设数组中无重复元素。
 *
 * 示例 1:
 * 输入: [1,3,5,6], 5
 * 输出: 2
 *
 * 示例 2:
 * 输入: [1,3,5,6], 2
 * 输出: 1
 *
 * 示例 3:
 * 输入: [1,3,5,6], 7
 * 输出: 4
 *
 * 示例 4:
 * 输入: [1,3,5,6], 0
 * 输出: 0
 *
 * 链接：https://leetcode-cn.com/problems/search-insert-position
 */
public class BinarySearch {

    /**
     * 二分查找
     *
     * @param sortedList 有序数组
     * @param search     待查找元素
     * @return 若找到, 返回元素索引, 未找到, 返回插入位置
     */
    public int binarySearch(int[] sortedList, int search) {
        // 标记查找范围
        int low = 0;
        int high = sortedList.length - 1;

        while (low <= high) {
            // 每次查找中间元素
            int mid = (low + high) / 2;
            if (sortedList[mid] == search) {
                return mid;
            } else if (sortedList[mid] < search) {
                low = mid + 1;
            } else if (sortedList[mid] > search) {
                high = mid - 1;
            }
        }
        return low;
    }

    public static void main(String args[]) {
        Scanner cin = new Scanner(System.in, "utf-8");
        String[] input = cin.nextLine().split(" ");

        String[] sortedListStr = input[0].substring(1, input[0].length()-2).split(",");
        int len = sortedListStr.length;
        int[] sortedList = new int[len];
        for (int i = 0; i < len; i++) {
            sortedList[i] = Integer.parseInt(sortedListStr[i]);
        }

        int search = Integer.parseInt(input[1]);

        BinarySearch bs = new BinarySearch();
        System.out.println(bs.binarySearch(sortedList, search));
    }
}
```

```java tab="29. 两数相除" hl_lines="66 67 68 73"
package search;

import java.util.Scanner;

/**
 * 29. 两数相除
 * <p>
 * 给定两个整数，被除数 dividend 和除数 divisor。将两数相除，要求不使用乘法、除法和 mod 运算符。
 * <p>
 * 返回被除数 dividend 除以除数 divisor 得到的商。
 * <p>
 * 示例 1:
 * 输入: dividend = 10, divisor = 3
 * 输出: 3
 * <p>
 * 示例 2:
 * 输入: dividend = 7, divisor = -3
 * 输出: -2
 * <p>
 * 示例 3:
 * 输入: dividend = -2147483648, divisor = -1
 * 输出: 2147483647
 * <p>
 * 示例 4:
 * 输入: dividend = -2147483648, divisor = 1
 * 输出: -2147483648
 * <p>
 * 示例 5:
 * 输入: dividend = -2147483648, divisor = 2
 * 输出: -1073741824
 * <p>
 * 说明:
 * 被除数和除数均为 32 位有符号整数。
 * 除数不为 0。
 * 假设我们的环境只能存储 32 位有符号整数，其数值范围是 [−231,  231 − 1]。
 * 本题中，如果除法结果溢出，则返回 231 − 1。
 * <p>
 * 链接：https://leetcode-cn.com/problems/divide-two-integers
 */
public class Divide {

    /**
     * 求商即求被除数中包含多少个除数
     *
     * @param dividend 被除数
     * @param divisor  除数
     * @return 商
     */
    public int divide(int dividend, int divisor) {
        int result = 0;

        // 特殊情况处理
        if (dividend == 0) {
            return 0;
        }
        if (Integer.MIN_VALUE == dividend && divisor == -1) {
            return Integer.MAX_VALUE;
        }

        // 先去掉符号, 注意先转换类型再计算
        long absDividend = Math.abs((long) dividend);
        long absDivisor = Math.abs((long) divisor);

        for (int i = 31; i >= 0; i--) {
            // 除以2^n^, 结果大于等于除数, 说明至少包含2^n^个除数
            if ((absDividend >> i) >= absDivisor) {
                result += (1 << i);
                absDividend -= (absDivisor << i);
            }
        }

        // 使用按位异或计算两数符号是否相同
        boolean negative = (dividend ^ divisor) < 0;
        return negative ? -result : result;
    }

    public static void main(String args[]) {
        Scanner cin = new Scanner(System.in, "utf-8");
        String[] inputStrList = cin.nextLine().split(",");

        int[] inputList = new int[2];
        inputList[0] = Integer.parseInt(inputStrList[0]);
        inputList[1] = Integer.parseInt(inputStrList[1]);

        Divide d = new Divide();
        System.out.println(d.divide(inputList[0], inputList[1]));
    }
}
```
