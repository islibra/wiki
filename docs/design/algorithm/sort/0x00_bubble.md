# 0x00_bubble

## 冒泡排序

> 两重循环不断将相邻元素中较大的元素交换到最后。

```python tab="标准版"
#!/usr/local/bin/python3


# 冒泡排序方法定义
def bubble(inlist):
    # 2. 总共进行1~length-1次比较即可
    for i in range(1, len(inlist)):
        # 1. 每轮循环从第一个元素开始比较，一直比到数组长度-循环次数，把最大元素移到最后
        # 如第一轮比到length-1-1，即去掉最后一个元素，range是左开右闭区间
        for j in range(0, len(inlist)-i):
            if inlist[j] > inlist[j+1]:
                # 复合赋值
                inlist[j], inlist[j+1] = inlist[j+1], inlist[j]
    return inlist


# 测试列表
input_list = [5, 4, 2, 3, 8]

print(bubble(input_list))
```

```python tab="已排序提前退出" hl_lines="10 18 20 22"
#!/usr/local/bin/python3


# 冒泡排序方法定义
def bubble(inlist):
    # 2. 总共进行1~length-1次比较即可
    for i in range(1, len(inlist)):
        print("round: ", i)
        # 优化1.1:
        isSorted = True
        # 1. 每轮循环从第一个元素开始比较，一直比到数组长度-循环次数，把最大元素移到最后
        # 如第一轮比到length-1-1，即去掉最后一个元素，range是左开右闭区间
        for j in range(0, len(inlist)-i):
            if inlist[j] > inlist[j+1]:
                # 复合赋值
                inlist[j], inlist[j+1] = inlist[j+1], inlist[j]
                # 优化1.2:
                isSorted = False
        # 优化1.3:
        if isSorted:
            print("already sorted, break")
            break
    return inlist


# 测试列表
input_list = [5, 8, 6, 3, 9, 1, 2, 7]

print(bubble(input_list))
```

```python tab="记录有序区索引" hl_lines="7 8 19 26 29"
#!/usr/local/bin/python3


# 冒泡排序方法定义
def bubble(inlist):
    # 优化2.1:
    indexLimit = len(inlist)-1
    lastExchangeIndex = 0
    # 2. 总共进行1~length-1次比较即可，range是左开右闭区间
    for i in range(1, len(inlist)):
        print("round:", i)
        # 优化1.1:
        isSorted = True
        # 1. 每轮循环从第一个元素开始比较，一直比到数组长度-循环次数，把最大元素移到最后
        # 如第一轮比到length-1-1，即去掉最后一个元素
        print("index limit:", indexLimit)
        # 优化2.2:
        j = 0
        while j < indexLimit:
            if inlist[j] > inlist[j+1]:
                # 复合赋值
                inlist[j], inlist[j+1] = inlist[j+1], inlist[j]
                # 优化1.2:
                isSorted = False
                # 优化2.3:
                lastExchangeIndex = j
            j += 1
        # 优化2.4:
        indexLimit = lastExchangeIndex
        # 优化1.3:
        if isSorted:
            print("already sorted, break")
            break
    return inlist


# 测试列表
input_list = [5, 8, 6, 3, 9, 1, 2, 7, 10, 11, 16, 15]

print(bubble(input_list))
```

- 时间复杂度：O(n^2^)
- 空间复杂度：O(1)

???+ check "适用场景"
    - 已排序提前退出：小区间有序
    - 记录有序区索引：大区间有序


## 鸡尾酒排序

> 双向冒泡

```python hl_lines="14 23 41"
#!/usr/local/bin/python3


# 鸡尾酒排序方法定义
def cocktail(inlist):
    # 优化2.1:
    leftIndexLimit = len(inlist)-1
    leftExchangeIndex = 0
    rightIndexLimit = 0
    rightExchangeIndex = len(inlist)-1

    # 区分奇数轮和偶数轮，总共进行1~length/2-1次比较即可
    # range是左开右闭区间
    for i in range(1, len(inlist)//2):
        print("round:", i)
        # 优化1.1:
        isSorted = True

        # 奇数轮从第一个元素开始比较，一直比到数组长度-循环次数，把最大元素移到最后
        # 如第一轮比到length-1-1，即去掉最后一个元素
        print("left index limit:", leftIndexLimit)
        # 优化2.2:
        for j in range(rightIndexLimit, leftIndexLimit):
            if inlist[j] > inlist[j+1]:
                # 复合赋值
                inlist[j], inlist[j+1] = inlist[j+1], inlist[j]
                # 优化1.2:
                isSorted = False
                # 优化2.3:
                leftExchangeIndex = j
        # 优化2.4:
        leftIndexLimit = leftExchangeIndex
        # 优化1.3:
        if isSorted:
            print("already sorted, break")
            break

        # 偶数轮从最后一个元素开始比较，一直比到第一个元素
        print("right index limit:", rightIndexLimit)
        # 优化2.2:
        for j in range(leftIndexLimit, rightIndexLimit, -1):
            if inlist[j] < inlist[j-1]:
                # 复合赋值
                inlist[j], inlist[j-1] = inlist[j-1], inlist[j]
                # 优化1.2:
                isSorted = False
                # 优化2.3:
                rightExchangeIndex = j
        # 优化2.4:
        rightIndexLimit = rightExchangeIndex
        # 优化1.3:
        if isSorted:
            print("already sorted, break")
            break
    return inlist


# 测试列表
input_list = [2, 3, 4, 5, 6, 7, 8, 1]

print(cocktail(input_list))
```

???+ check "适用场景"
    大部分元素已经有序


???+ quote "参考链接"
    - [漫画：什么是冒泡排序？](https://mp.weixin.qq.com/s/wO11PDZSM5pQ0DfbQjKRQA)
    - [漫画：什么是鸡尾酒排序？（修订版）](https://mp.weixin.qq.com/s/CoVZrvis6BnxBQgQrdc5kA)
