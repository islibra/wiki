# 0x02_quick

## 快速排序

- 基线条件: 数组长度为0或1
- 递归条件: 以第一个元素作为基准值，把数组划分为小于基准值和大于基准值两个子数组，分治。

```java
package sort;

import java.util.Arrays;

/**
 * 快速排序
 */
public class QuickSort {

    private int[] append(int[] s, int pivot, int[] b) {
        int len = s.length + b.length + 1;
        int[] result = new int[len];
        System.arraycopy(s, 0, result, 0, s.length);
        result[s.length] = pivot;
        System.arraycopy(b, 0, result, s.length + 1, b.length);
        return result;
    }

    private int[] sort(int[] ary) {
        int len = ary.length;
        if (len < 2) {
            return ary;
        } else {
            // 基准值
            int pivot = ary[0];
            // 比基准值小
            int[] small = new int[len];
            int slen = 0;
            // 比基准值大
            int[] big = new int[len];
            int blen = 0;
            for (int i = 1; i < ary.length; i++) {
                if (ary[i] < pivot) {
                    small[slen] = ary[i];
                    slen++;
                } else if (ary[i] > pivot) {
                    big[blen] = ary[i];
                    blen++;
                }
            }
            return append(sort(Arrays.copyOf(small, slen)), pivot, sort(Arrays.copyOf(big, blen)));
        }
    }

    public static void main(String args[]) {
        QuickSort qs = new QuickSort();

        int[] ary = new int[]{9, 2, 5, 7, 4};
        System.out.println(Arrays.toString(qs.sort(ary)));
    }
}
```

## 时间复杂度

- 平均复杂度O(nlogn): logn为递归调用的层数
- 最坏复杂度O(n^2^): 选择的基准值不总是中间值, 无法将两个子数组平均分开, 递归调用的层数与元素个数相当

> 合并排序O(nlogn)，但常量C大于快排。
