# yaml

???+ tip
    不关心缩进的空格数，相同层级元素对齐即可。

## 注释

`#`

## 数据结构

### map

```yaml
xxx: yyy  # 如果包含空格或特殊字符，需放在引号之中，如：'hello\nworld'
```

### list

```yaml
- Cat
- Dog
- Goldfish
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
```
