# 字符串

- 重复：`"repeatstring"*3`
- 索引：  
```python
str = "abcdefg"
print(str[0], str[-1], str[2:5])  #切片前闭后开

###
a g cde
```

字符串不能改变，如`word[0] = 'm'`会导致错误。

## 字符串处理

```python
# 转换为字符串
print('hello ' + str(99))
print('hello2 ' + repr(50))
print('1'.rjust(3))  # 右对齐
print('2'.center(3))  # 居中
print('3'.ljust(3))  # 左对齐
print('12'.zfill(5))  # 0填充
# 格式化字符串
print('This is a {} length string, and its value is {}'.format(3, 'abc'))
# 指定位置和关键字
print('This is another {1} length string, and its value is {0}, also {str} is 3.'.format('abc', 3, str='def'))
# 宽度和类型
print('{0:10} ==> {1:10d}'.format('jack', 4097))
```


# 列表

```python
alist = [123, "astring", 4.5, True]
print(alist)

###
[123, 'astring', 4.5, True]
```

与字符串一样可以索引，切片，使用`+`串联，元素可以改变如`a[0] = 9`, `a[2:5] = [13, 14, 15]`, `a[2:5] = []`。

# 元组

```python
atuple = (123, "astring", 4.5, True)
print(atuple, type(atuple), len(atuple))
tup1 = ()  # 空元组
tup2 = (1,)  # 一个元素，需要在元素后添加逗号

###
(123, 'astring', 4.5, True) <class 'tuple'> 4
```

元素不可修改

# 集合

无序，去重

```python
student = set()  # 创建一个空集合

teacher = {"Alice", "Bob", "Cavin"}
print(teacher, "Bob" in teacher)  # 成员测试

# 集合运算
a = set('abcdefg')
b = set('def')
print(a, b, a-b, a|b, a&b, a^b)  # 差集，并集，交集，余集

###
{'Alice', 'Cavin', 'Bob'} True
{'c', 'b', 'a', 'g', 'f', 'd', 'e'} {'d', 'e', 'f'} {'c', 'a', 'b', 'g'} {'c', 'b', 'a', 'g', 'f', 'd', 'e'} {'d', 'e', 'f'} {'c', 'b', 'a', 'g'}
```

# 字典

无序，键值对集合

```python
dic = {}  # 创建空字典

tel = {'Jack':9999, 'Alice':1234, 'Bob':5678, 'Cavin':9012}
print(tel)

print(tel['Bob'])  # 索引

tel['David'] = 3456  # 添加
del tel['Alice']  # 删除
print(tel)

print(list(tel.keys()))  # 返回key列表

print(sorted(tel.keys()))  # key排序

print('Jack' in tel, 'Alice' not in tel)  # 成员测试

###
{'Jack': 9999, 'Alice': 1234, 'Bob': 5678, 'Cavin': 9012}
5678
{'Jack': 9999, 'Bob': 5678, 'Cavin': 9012, 'David': 3456}
['Jack', 'Bob', 'Cavin', 'David']
['Bob', 'Cavin', 'David', 'Jack']
True True
```

构造函数

```python
dic1 = dict([('sape', 4139), ('guido', 4127), ('jack', 4098)])
print(dic1)

dic2 = {x:x**2 for x in (2,4,6)}
print(dic2)

dic3 = dict(sape=4139, guido=4127, jack=4098)
print(dic3)

###
{'sape': 4139, 'guido': 4127, 'jack': 4098}
{2: 4, 4: 16, 6: 36}
{'sape': 4139, 'guido': 4127, 'jack': 4098}
```
