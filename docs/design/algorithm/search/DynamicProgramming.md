# DynamicProgramming

!!! abstract "动态规划"

## 0-1背包问题

背包容量35磅(**限制条件**), 装入价值最高(**期望**)的商品

- 音响: 30磅(**开销**), $3000
- 笔记本电脑: 20磅, $2000
- 吉他: 15磅, $1500

> 找出所有的排列组合, 时间复杂度O(2^n^)

### 动态规划解决0-1背包问题

以重量（**限制条件**）为列，商品为行，计算每个单元格（**价值**），其中 ^^列需要划分为最小单位^^。

计算公式：`cell[i][j] = cell[i-1][j](前一行, 不包含当前商品时) VS 当前商品价值 + cell[i-1][j-当前商品重量](前一行, 剩余空间的价值)`

> 增加商品时只需增加行

```java
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 背包, 4磅
 * 吉他, 1磅, $1500
 * 音响, 4磅, $3000
 * 笔记本电脑, 3磅, $2000
 * IPHONE, 1磅, $2000
 */
public class DynamicProgramming {

    public static void main(String args[]) {
        // 背包容量
        final int capcity = 4;

        // 商品重量
        Map<String, Integer> weight = new HashMap<>();
        weight.put("guitar", 1);
        weight.put("audio", 4);
        weight.put("notebook", 3);
        weight.put("iphone", 1);

        // 商品价值
        Map<String, Integer> price = new HashMap<>();
        price.put("guitar", 1500);
        price.put("audio", 3000);
        price.put("notebook", 2000);
        price.put("iphone", 2000);

        // 获取商品数量
        int row = weight.size();
        System.out.println(row);

        // 创建表格
        int[][] table = new int[row][capcity];
        int i = 0;
        Set<String> keys = weight.keySet();
        for (String key : keys) {
            for (int j = 0; j < capcity; j++) {
                // 第一行直接填入
                if (i == 0) {
                    // 获取商品重量, 无法装下
                    if (j + 1 < weight.get(key)) {
                        table[i][j] = 0;
                    } else {
                        // 可以装下, 获取商品价值
                        table[i][j] = price.get(key);
                    }
                } else {
                    // 无法装下
                    table[i][j] = table[i - 1][j];
                    // 可以装下, 计算
                    if (j + 1 >= weight.get(key)) {
                        int newprice = price.get(key);
                        // 获取剩余容量
                        if (j + 1 > weight.get(key)) {
                            newprice += table[i - 1][j - weight.get(key)];
                        }
                        // 比较, 更新最大价值
                        if (newprice > table[i - 1][j]) {
                            table[i][j] = newprice;
                        }
                    }
                }
            }
            i++;
        }
        System.out.println(table[row - 1][capcity - 1]);
    }
}
```

## 旅游行程最优化

总共7天时间(**限制条件**), 去评分最高(**期望**)的景点游玩

- 威尼斯教堂, 0.5天(**开销**), 7分
- 环球剧场, 0.5天, 6分
- 国家美术馆, 1天, 9分
- 大英博物馆, 2天, 9分
- 圣保罗大教堂, 0.5天, 8分

> 动态规划不适合解决存在依赖关系的问题

## LongestCommonSubstring最长公共子串（连续）

- HISH <> FISH = ISH
- HISH <> VISTA = IS

公式: 行列值不同为0，相同为`cell[i-1][j-1] + 1`

!!! tip "最终答案不一定在右下角, 因此需要记录最长值"

```java
public class LongestCommonSubstring {

    public static void main(String args[]) {
        String srcStr = "FISH";
        //String dstStr = "HISH";
        //String dstStr = "VISTA";
        String dstStr = "HSHEL";
        char[] srcChars = srcStr.toCharArray();
        char[] dstChars = dstStr.toCharArray();

        // 创建表格
        int column = srcStr.length();
        int row = dstStr.length();
        int[][] table = new int[row][column];

        int maxi = 0;
        int maxj = 0;
        int maxValue = 0;

        for (int i = 0; i < row; i++) {
            for (int j = 0; j < column; j++) {

                table[i][j] = 0;

                // 字符相同
                if (dstChars[i] == srcChars[j]) {
                    // 第一行或第一列
                    if (i == 0 || j == 0) {
                        table[i][j] = 1;
                    } else {
                        table[i][j] = table[i - 1][j - 1] + 1;
                    }

                    if (table[i][j] > maxValue) {
                        maxValue = table[i][j];
                        maxi = i;
                        maxj = j;
                    }
                }
            }
        }

        System.out.println(maxi);
        System.out.println(maxj);
        System.out.println(maxValue);
        for (int k = maxValue - 1; k >= 0; k--) {
            System.out.print(srcChars[maxj - k]);
        }
        System.out.println();
    }
}
```

## LongestCommonSequence最长公共子序列（不连续）

行列值不同为上左取最大，相同为`cell[i-1][j-1] + 1`

应用：DNA测序，git diff，论文查重
