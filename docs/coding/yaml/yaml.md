# yaml

!!! tip "不关心 {==缩进==} 的空格数，相同层级元素对齐即可。"

## 注释

`#`

## 数据结构

### 字符串

```yaml
name: xxx
group: example.com
version: v1
```

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

!!! quote "参考链接: [YAML语法学习](https://mp.weixin.qq.com/s?src=11&timestamp=1589525347&ver=2339&signature=3b-LR8zyOM4LPpVwTAoSrAlZYseOgv-E-xpuV8Ga4fx0xh4xrXhOHMjuX1WQYsKdgRGsurNNfKHlAvZpSuTC24TBqKzPUE9TtLk6-TUs7mqRqA38KzleQ9V8wkCTJto4&new=1)"
