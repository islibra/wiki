# 0x00_bubble

冒泡排序：两重循环不断将相邻元素中较大的元素交换到最后。

```python
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
