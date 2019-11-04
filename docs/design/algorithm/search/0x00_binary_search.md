# 0x00_binary_search

!!! abstract "典型应用: 在{==有序==}的集合中查找"

时间复杂度: O(log~2~n)

!!! note "时间复杂度: 大O表示法, O表示运行时间的{==增速==}，代表{==最糟情况下运行时间==}"
    - O(1), 常量级
    - O(logn), 对数级
    - O(n), 线性级
    - O(nlogn)
    - O(n^2^), 指数级
    - O(n!), 阶乘级，如旅行商问题

## 代码示例

```java tab="Java"
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
