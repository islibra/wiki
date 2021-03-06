# 0x02_hashtable

## 散列函数

将输入映射到数字

- 相同的输入散列值相同
- 不同的输入散列值不同
- 可设置散列值的范围

### 常见散列函数

- MD5
- SHA1

求hash，再对数组大小(2的幂)求余。


## 散列表

将散列值作为 **数组下标** 存储数据

- 查找复杂度O(1)
- 不保证数据有序, 查找最大/小值为O(n)

### 各语言实现: 键值对(映射, 字典dict)

```python tab="Python"
book = dict()
book["apple"] = 0.67
book["milk"] = 1.49
# {'apple': 0.67, 'milk': 1.49}
print(book)
# 1.49
print(book["milk"])
```

[Java](../../../coding/java/lib/Hashtable/)

## 应用

- 查找(键无序): 电话簿, DNS解析
- 去重: 投票
- 缓存

## 散列冲突

不同的输入映射到相同的值

### 链表

最坏复杂度O(n)

### 开放寻址

#### 线性探测，依次往后找，O(n)

## 填装因子

包含元素数 / 数组大小

大于1时产生散列冲突, 需要存储的数据大于存储区域

## 调整

1. 将数组增大一倍
1. 重新计算hash

## LeetCode

```java tab="136. 只出现一次的数字"
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * 136. 只出现一次的数字
 * 给定一个非空整数数组，除了某个元素只出现一次以外，其余每个元素均出现两次。找出那个只出现了一次的元素。
 *
 * 说明：
 * 你的算法应该具有线性时间复杂度。 你可以不使用额外空间来实现吗？
 *
 * 示例 1:
 * 输入: [2,2,1]
 * 输出: 1
 *
 * 示例 2:
 * 输入: [4,1,2,1,2]
 * 输出: 4
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/single-number
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 */
public class OnlyOneNum {

    public int singleNumber(int[] nums) {
        Hashtable table = new Hashtable();
        for (int i : nums) {
            // 注意必须要使用containsKey
            if (table.containsKey(i)) {
                table.remove(i);
            } else {
                table.put(i, 1);
            }
        }
        int result = 0;
        Enumeration e = table.keys();
        while (e.hasMoreElements()) {
            result = (int) e.nextElement();
        }
        return result;
    }

    public static void main(String args[]) {
//        int[] nums = {2, 2, 1};
        int[] nums = {4, 1, 2, 1, 2};
        OnlyOneNum oon = new OnlyOneNum();
        System.out.println(oon.singleNumber(nums));
    }
}
```

```java tab="202. 快乐数"
import java.util.HashSet;

/**
 * 202. 快乐数
 * 编写一个算法来判断一个数是不是“快乐数”。
 * 一个“快乐数”定义为：对于一个正整数，每一次将该数替换为它每个位置上的数字的平方和，然后重复这个过程直到这个数变为 1，也可能是无限循环但始终变不到 1。如果可以变为 1，那么这个数就是快乐数。
 *
 * 示例: 
 * 输入: 19
 * 输出: true
 *
 * 解释:
 * 12 + 92 = 82
 * 82 + 22 = 68
 * 62 + 82 = 100
 * 12 + 02 + 02 = 1
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/happy-number
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 */
public class HappyNum {

    public int compute(int input) {
        int result = 0;
        // 将数字转换成字符串
        String s = String.valueOf(input);
        // 将字符串拆分成字符数组
        char[] cArray = s.toCharArray();
        // 将字符数组转换回数字
        for (char c : cArray) {
            int i = Character.getNumericValue(c);
            result += Math.pow(i, 2);
        }
        return result;
    }

    public boolean isHappy(int n) {
        HashSet set = new HashSet();
        int result = compute(n);
        while (result != 1) {
            if (set.contains(result)) {
                return false;
            }
            set.add(result);
            result = compute(result);
        }
        return true;
    }

    public static void main(String[] args) {
        HappyNum happyNum = new HappyNum();
        System.out.println(happyNum.isHappy(19));
    }
}
```
