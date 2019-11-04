# 0x00_binary_search

!!! abstract "典型应用: 在{==有序==}的{==数组(随机访问)==}中查找"

时间复杂度: O(log~2~n)

!!! note "时间复杂度: 大O表示法, O表示运行时间的{==增速==}，代表{==最糟情况下运行时间==}"
    - O(1), 常量级
    - O(logn), 对数级: 二分查找
    - O(n), 线性级: 简单查找
    - O(nlogn): 快速排序
    - O(n^2^), 指数级: 选择排序
    - O(n!), 阶乘级: 旅行商问题

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

```java
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
