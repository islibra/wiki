# array_list

## 数组

- 大小固定, 无法动态扩展(扩容)
- 无法在任意位置插入删除, 需移动后面所有元素, **顺序写O(n)**
- {==可直接读取指定索引的元素==}, **随机读O(1)**

!!! example "适用于查找排序"

## 链表

- 每个元素存储了下一个元素的地址, 增加了空间开销, 可{==动态扩展==}(扩容)
- {==可在任意位置插入删除==}, **随机写O(1)**
- 无法直接读取中间某个元素, 查找时需要遍历整个链表, **顺序读O(n)**

!!! example "适用于实现队列"

- 单向链表
- 双向链表
- 循环链表
- 十字链表


## LeetCode

```java
import java.util.Arrays;
import java.util.Scanner;

/**
 * 1. 两数之和
 * 给定一个整数数组 nums 和一个目标值 target，请你在该数组中找出和为目标值的那 两个 整数，并返回他们的数组下标。
 * <p>
 * 你可以假设每种输入只会对应一个答案。但是，你不能重复利用这个数组中同样的元素。
 * <p>
 * 示例:
 * <p>
 * 给定 nums = [2, 7, 11, 15], target = 9
 * <p>
 * 因为 nums[0] + nums[1] = 2 + 7 = 9
 * 所以返回 [0, 1]
 * <p>
 * 链接：https://leetcode-cn.com/problems/two-sum
 */
public class TwoSum {

    public int[] twoSum(int[] nums, int target) {
        int[] result = new int[2];
        for (int i = 0; i < nums.length - 1; i++) {
            for (int j = i + 1; j < nums.length; j++) {
                if (nums[j] == target - nums[i]) {
                    result[0] = i;
                    result[1] = j;
                    return result;
                }
            }
        }
        return result;
    }

    public static void main(String args[]) {
        Scanner cin = new Scanner(System.in, "utf-8");
        String[] input = cin.nextLine().split(",");
        int len = input.length;
        int[] nums = new int[len];
        for (int i = 0; i < len; i++) {
            nums[i] = Integer.parseInt(input[i]);
        }

        int target = Integer.parseInt(cin.nextLine());

        TwoSum ts = new TwoSum();
        System.out.println(Arrays.toString(ts.twoSum(nums, target)));
    }
}
```
