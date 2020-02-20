# Greedy



- 旅行商问题，每次选取距离当前城市最近的解

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
- ...

每个广播台覆盖的区域可能重叠，如何找出覆盖所有集合(**限制条件**)的最少(**期望**)广播台。

### 思想

每次查找与 **剩余集合** {==交集最多==}的 **广播台**(**局部最优解**)

- states_needed = set[]
- stations = {station["kone"] = set[], station["ktwo"] = set[]}
- final_stations = set[]
- while states_needed is not empty
    - for stations
        - best_station, states_covered = MAX(states_needed & states_instation)

## 0-1背包问题

背包容量35磅(**限制条件**), 装入价值最高(**期望**)的商品

- 音响: 30磅(**开销**), $3000
- 笔记本电脑: 20磅, $2000
- 吉他: 15磅, $1500
