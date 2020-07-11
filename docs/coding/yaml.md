# yaml

!!! tip "不关心 {==缩进==} 的空格数，相同层级元素 {==对齐==} 即可。"

## I. 注释

`#`

## I. 数据结构

### II. 字符串

```yaml
name: xxx
group: example.com
version: v1
```

#### III. 多行字符串

```yaml
example1: This is a long long \
         string.
```

```yaml
# 可以用单引号或双引号
example2: 'This is a long long
          string.'
```

```yaml
# 文末新增一空行
example3: >
  This is a long long
  string.

# 文末新增两空行
example3: >+
  This is a long long
  string.

# 文末不新增空行
example3: >-
  This is a long long
  string.
```

#### III. 换行

```yaml
# 必须用双引号反转义
example: "This is a string.\n \
         This is another string."
```

#### III. 段落

```yaml
# 文末新增一空行
example: |
  This is a string.
  This is another string.

# 文末新增两空行
example: |+
  This is a string.
  This is another string.

# 文末不新增空行
example: |-
  This is a string.
  This is another string.
```

!!! quote "[YAML中多行字符串的配置方法](https://www.cnblogs.com/didispace/p/12524194.html)"


### 数组list

```yaml
skill:
    - Python
    - Golang
    - Java
```

### 字典map

```yaml
# 如果包含空格或特殊字符，需放在引号之中，如：'hello\nworld'
info:
    basic_info:
        name: kingname
        age: 27
    other_info:
        address: 杭州
        salary: 99999.0
```

### 标量

null: `~`

### 复合结构

```yaml
languages:  # 值为list
    - Ruby
    - Perl
    - Python
websites:  # 值为map
    YAML: yaml.org
    Ruby: ruby-lang.org
    Python: python.org
    Perl: use.perl.org
companies: # 由map组成的list
  - id: 1
    name: company1
  - id: 2
    name: company2
```

!!! quote "参考链接"
    - [YAML语法学习](https://mp.weixin.qq.com/s?src=11&timestamp=1589525347&ver=2339&signature=3b-LR8zyOM4LPpVwTAoSrAlZYseOgv-E-xpuV8Ga4fx0xh4xrXhOHMjuX1WQYsKdgRGsurNNfKHlAvZpSuTC24TBqKzPUE9TtLk6-TUs7mqRqA38KzleQ9V8wkCTJto4&new=1)
    - [JSON to YAML](https://www.json2yaml.com/)
