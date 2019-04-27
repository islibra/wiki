# mkdocs

内置开发服务器，实时预览。

## 安装

1. 安装Python和包管理器pip  
```bash
$ python --version
Python 2.7.2
$ pip --version
pip 1.5.2
```
2. 安装mkdocs  
```bash
pip --proxy=http://l0025xxxx:pass\@word@proxy.xxx.com:8080 install mkdocs

$ mkdocs --version
mkdocs, version 0.15.3
```

## 创建项目

```bash
mkdocs new my-project
cd my-project
$ mkdocs serve  #启动服务器
```

## 目录组织方式

```yaml
mkdocs.yml  #配置nav菜单，默认所有目录按字母排序
docs/
    index.md  #会被渲染为index.html，也可用README.md代替
```

## 导航配置示例

```yaml
nav:
- Home: 'index.md'
- User Guide:
    - 'Writing your docs': 'writing-your-docs.md'
    - 'Styling your docs': 'styling-your-docs.md'
- About:
    - 'License': 'license.md'
    - 'Release Notes': 'release-notes.md'
```

## 更换主题

```bash
pip install mkdocs-material
```

## 扩展库

```bash
pip install pymdown-extensions
```

### 修改配置

```yaml
site_name: 'islibra'
site_author: '李晓龙'
site_url: 'https://islibra.github.io/hello-islibra/'

# 源码地址
repo_name: 'islibra/wiki'
repo_url: 'https://github.com/islibra/wiki'
edit_uri: 'blob/master/docs/'

# Copyright
copyright: 'Copyright &copy; 2018 - 2019 李晓龙'

#主题
theme:
  name: 'material'
  language: 'zh'  # 配置语言
  palette:  # 颜色
    primary: 'cyan'
    accent: 'red'
  logo:
    icon: 'cloud'
  feature:
    tabs: true  # 横向导航

extra:
  disqus: 'islibra'  # 评论

google_analytics:
  - 'UA-XXXXXXXX-X'
  - 'auto'

markdown_extensions:
  - admonition  # 提示块
  - footnotes  # 脚注
  - meta  # 定义元数据，通过文章上下文控制，如disqus
  - pymdownx.caret  # 下划线上标
  - pymdownx.tilde  # 删除线下标
  - pymdownx.critic  # 增加删除修改高亮注释，可修饰行内或段落
  - pymdownx.details  # 提示块可折叠
  - pymdownx.inlinehilite  # 行内代码高亮
  - pymdownx.mark  # 文本高亮
  - pymdownx.smartsymbols  # 符号转换
  - pymdownx.superfences  # 代码嵌套在列表里
  - codehilite:    # 代码高亮，显示行号
      guess_lang: false
      linenums: true
  - toc:  # 锚点
      permalink: true
#  - pymdownx.arithmatex  # 数学公式
  - pymdownx.betterem:  # 对加粗和斜体更好的检测
      smart_enable: all
#  - pymdownx.emoji:  # 表情
#      emoji_generator: !!python/name:pymdownx.emoji.to_svg
#  - pymdownx.magiclink  # 自动识别超链接
  - pymdownx.tasklist:  # 复选框checklist
      custom_checkbox: true
```

## MD语法

### MkDocs特色

- 超链接可使用相对路径如：`Please see the [project license](../about/license.md) for further details.`
- 超链接可使用锚点如：`Please see the [project license](about.md#license) for further details.`
- 标题查找顺序：  
    1. nav配置
    2. meta-data
    3. level 1 Markdown header on the first line
    4. 文件名

### YAML Style Meta-Data

```
---
title: My Document
summary: A brief description of my document.
authors:
    - Waylan Limberg
    - Tom Christie
date: 2018-07-10
some_url: https://example.com
---
This is the first paragraph of the document.
```

### 语法习惯

1. 元数据写在H1之前如：  
```
hero: xxx顶部超级提示
path: tree/master/docs/extensions源代码相对路径
source: metadata.md底部显示源码链接，需在mkdocs.yml repo_url中定义
disqus:空disable

# H1
```
1. 使用H1做title
1. 符号参见[SmartSymbols](#smartsymbols)
1. 文本修饰
    - 高亮`==mark me==`, 下划线`^^Insert me^^`, 删除线`~~Delete me~~`
    - 增加`{++add++}`, 删除`{--del--}`, 修改`{~~is~>are~~}`, 高亮`{==highlight==}`, 注释`{>>comment<<}`，可修饰行内或段落
    - 上标`H^2^0`, `text^a\ superscript^`, 下标`CH~3~CH~2~OH`, `text~a\ subscript~`
    - 行内代码高亮：`` `:::language mycode` `` or `` `#!language mycode` ``
2. 一级列表使用`-`，二级列表使用`*`，三级列表使用`+`，子级列表缩进 **4** 个空格，使用复选框：`- [x] item`
3. 代码块添加`tab="xxx"`分组，添加`hl_lines="3 4"`高亮行
    - 嵌套在列表中
    ```
    - list1
        - sublist1
        ```
        code
        ```
        - sublist2
    - list2
    ```
1. 表格  
```
First Header | Second Header | Third Header
:----------- |:-------------:| -----------:
Left         | Center        | Right
```
1. 提示块参见[Admonition](#admonition)
4. 脚注`[^1]`，脚注可定义在任意位置，单行`[^1]: xxx`，多行每行开头4个空格，链接形式`https://xxx/#fn:1`


### Admonition

示例：  
```
!!! type ["custom title or blank"]
    text

# 可折叠，+默认打开
???[+] type ["custom title or blank"]
    text
```

- abstract, summary, tldr: 摘要，段落
- tip, hint, important: 贴士，火种
- note, seealso: 注释，笔
- example, snippet: 举例，列表
- quote, cite: 引用，引号
- info, todo: 提示，叹号
- warning, caution, attention: 警告，叹号
- danger, error: 危险，闪电
- question, help, faq: 问题，问号
- success, check, done: 成功，对勾
- failure, fail, missing: 失败，叉叉
- bug: 虫虫

### SmartSymbols

Markdown       | Result
-------------- |--------
`(tm)`         | (tm)
`(c)`          | (c)
`(r)`          | (r)
`c/o`          | c/o
`+/-`          | +/-
`-->`          | -->
`<--`          | <--
`<-->`         | <-->
`=/=`          | =/=
`1/4, etc.`    | 1/4, etc.
`1st 2nd etc.` | 1st 2nd etc.


## 构建

```bash
mkdocs build  # 生成site目录
echo "site/" >> .gitignore  # 忽略site文件夹提交
mkdocs build --clean  # 清理目录
```

## 部署

### 分支部署

```bash
mkdocs gh-deploy  # 新建gh-pages分支
```

### 单独仓部署

```bash
cd ../orgname.github.io/  # 切换到仓目录
mkdocs gh-deploy --config-file ../my-project/mkdocs.yml --remote-branch master
```


!!! quote "参考链接"
    - CTF WIKI: <https://ctf-wiki.github.io/ctf-wiki/>
    - 官方网站：<https://www.mkdocs.org/>
    - 主题：<https://squidfunk.github.io/mkdocs-material/>
