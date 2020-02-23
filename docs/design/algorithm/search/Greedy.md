# Greedy

!!! abstract "贪婪算法, 解决{==NP完全问题==}"

## 背包问题

先计算单位价值，从大到小排列

## 资源调度问题

在同一间教室的一个时间段如9:00 - 12:00(**限制条件**), 安排尽可能多(**期望**)的课程

- 美术: 9:00 - 10:00(**开销**)
- 英语: 9:30 - 10:30
- 数学: 10:00 - 11:00
- 计算机: 10:30 - 11:30
- 音乐: 11:00 - 12:00

### 思想

在所有剩余课程里, 找到结束最早的课程(**局部最优解**)

## 集合覆盖问题

- KONE: ID, NV, UT(**覆盖范围**)
- KTWO: WA, ID, MT
- KTHREE: OR, NV, CA
- KFOUR: NV, UT
- KFIVE: CA, AZ

每个广播台覆盖的区域可能重叠，如何找出覆盖所有集合(**限制条件**)的最少(**期望**)广播台。

### 思想

每次查找与 **剩余集合** {==交集最多==}的 **广播台**(**局部最优解**)

```java
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Greedy {

    public static void main(String[] args) {
        // 要覆盖的所有州
        Set<String> statesNeeded = new HashSet<>();
        statesNeeded.add("mt");
        statesNeeded.add("wa");
        statesNeeded.add("or");
        statesNeeded.add("id");
        statesNeeded.add("nv");
        statesNeeded.add("ut");
        statesNeeded.add("ca");
        statesNeeded.add("az");
        System.out.println(statesNeeded);

        // 广播台的覆盖能力
        Map<String, Set<String>> stations = new HashMap<>();
        Set<String> kone = new HashSet<>();
        kone.add("id");
        kone.add("nv");
        kone.add("ut");
        stations.put("kone", kone);
        Set<String> ktwo = new HashSet<>();
        ktwo.add("wa");
        ktwo.add("id");
        ktwo.add("mt");
        stations.put("ktwo", ktwo);
        Set<String> kthree = new HashSet<>();
        kthree.add("or");
        kthree.add("nv");
        kthree.add("ca");
        stations.put("kthree", kthree);
        Set<String> kfour = new HashSet<>();
        kfour.add("nv");
        kfour.add("ut");
        stations.put("kfour", kfour);
        Set<String> kfive = new HashSet<>();
        kfive.add("ca");
        kfive.add("az");
        stations.put("kfive", kfive);

        // 最终选择的广播台
        Set<String> finalStations = new HashSet<>();

        // 贪婪算法
        while (!statesNeeded.isEmpty()) {
            String maxStation = null;
            Set<String> statesCovered = new HashSet<>();

            // 遍历所有剩余广播台
            Set<String> keys = stations.keySet();
            for (String key : keys) {
                Set<String> states = stations.get(key);

                // 获取交集
                Set<String> mixed = new HashSet<>();
                mixed.addAll(statesNeeded);
                mixed.retainAll(states);

                // 找到覆盖更多的广播台
                if (mixed.size() > statesCovered.size()) {
                    maxStation = key;
                    statesCovered.clear();
                    statesCovered.addAll(mixed);
                }
            }

            finalStations.add(maxStation);
            stations.remove(maxStation);
            statesNeeded.removeAll(statesCovered);
        }

        System.out.println(finalStations);
    }
}
```

## 旅行商问题

找出前往5个不同城市(每个城市经过且仅经过一次)的最短路径

> 起点未知

> A --> B != B --> A

!!! abstract "时间复杂度: O(n!)"

### 思想

随机选取一个出发城市, 每次选取距离当前城市最近的解
