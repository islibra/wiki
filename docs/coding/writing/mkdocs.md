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
pip --proxy=http://l0025xxxx:pass%40word@proxy.xxx.com:8080 install mkdocs  # %40代表@

$ mkdocs --version
mkdocs, version 0.15.3
```

## 创建项目

```bash
mkdocs new my-project
cd my-project
$ mkdocs serve --dirtyreload  # 启动服务器
$ mkdocs serve -a 127.0.0.1:8001  # 启动第二个服务器，占用8001端口
```

!!! tip "serve缓存路径"
    `C:\Users\xxx\AppData\Local\Temp\mkdocs_xxx`

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

# 扩展样式
extra_css:
  - 'stylesheets/extra.css'

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

### 添加评论

1. 申请[GitHub Application](https://github.com/settings/applications/new)
    1. Application name: 应用名称
    1. Homepage URL: BLOG地址，如<https://islibra.github.io/hello-islibra/>
    1. Application description: 描述
    1. Authorization callback URL: 回调地址，同BLOG地址
1. Github - New repository，新建`comment`仓。
1. 修改文件路径：`C:\Users\xxx\AppData\Local\Programs\Python\Python37-32\Lib\site-packages\material\partials\integrations\disqus.html`

```html
<!--读取配置文件-->
{% set disqus = config.extra.disqus %}
<!--meta可以覆盖全局配置-->
{% if page and page.meta and page.meta.disqus is string %}
  {% set disqus = page.meta.disqus %}
{% endif %}

<!--首页不显示-->
{% if not page.is_homepage and disqus %}
{% set pageID = page.title | default("404", true) %}
  <!--outline-->
  <h2 id="__comments" data-no-instant>{{ lang.t("meta.comments") }}</h2>
  <form id="gitalk-form" onsubmit="return false;" data-no-instant>
    <div id="gitalk-container" data-no-instant></div>
  </form>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/gitalk@latest/dist/gitalk.min.css">
  <script src="https://cdn.jsdelivr.net/npm/gitalk@latest/dist/gitalk.min.js"></script>
  <script>
    const gitalk = new Gitalk({
      clientID: 'xxx',
      clientSecret: 'xxx',
      repo: 'comment',  // 使用单独的仓评论
      owner: 'islibra',  // 仓库所有者
      admin: ['islibra'],  // 仓库管理员列表
      id: '{{ page.title | default("404", true)  }}',  // 页面唯一标识
      distractionFreeMode: false,  // 全屏遮罩效果
      pagerDirection: 'last'  // 排序方式：first按评论创建时间正序，last倒序
    })
    gitalk.render('gitalk-container')
  </script>
{% endif %}
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
1. 自定义标签：<https://shields.io/>，`https://img.shields.io/badge/<LABEL>-<MESSAGE>-<COLOR>.svg`
1. 符号参见[SmartSymbols](#smartsymbols)
1. 文本修饰
    - 高亮`==mark me==`, 下划线`^^Insert me^^`, 删除线`~~Delete me~~`
    - 增加`{+` `+` `add` `+` `+}`, 删除`{-` `-` `del` `-` `-}`, 修改`{~` `~` `is` `~` `>` `are` `~` `~}`, 高亮`{=` `=` `highlight` `=` `=}`, 注释`{>` `>` `comment` `<` `<}`，可修饰行内或段落
    - 上标`H^2^0`, `text^a\ superscript^`, 下标`CH~3~CH~2~OH`, `text~a\ subscript~`
    - 行内代码高亮：`` `:::language mycode` `` or `` `#!language mycode` ``
2. 一级列表使用`-`，二级列表使用`*`，三级列表使用`+`，子级列表缩进 **4** 个空格，使用复选框：`- [x] item`  
列表内容换行：==行尾2个空格==。
3. 代码块添加`tab="xxx"`分组，添加`hl_lines="3 4"`高亮行
    - 代码块嵌套在列表中，==缩进4个空格==
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

示例，==前后要有空行==，如果嵌套在列表中，==缩进4个空格==：  
```
!!! type ["custom title or blank"]
    text

# 可折叠，+默认打开
???[+] type ["custom title or blank"]
    text
```

??? abstract "摘要，总结"
    abstract, summary, tldr

??? tip "贴士"
    tip, hint, important

??? note "注释，代码片段，说明"
    note, snippet, seealso

??? example "举例"
    example

??? quote "引用，参考链接"
    quote, cite

??? info "提示，TODO"
    info, todo

??? warning "警告"
    warning, caution, attention

??? danger "危险"
    danger, error

??? success "成功，勾选，完成"
    success, check, done

??? fail "失败"
    failure, fail, missing

??? faq "问题，疑问，帮助"
    question, help, faq

??? bug "BUG"
    bug


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
