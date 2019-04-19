---
title: mkdocs
---

内置开发服务器，实时预览。

# 安装

1. 安装Python和包管理器pip  
```bash
$ python --version
Python 2.7.2
$ pip --version
pip 1.5.2
```
2. 安装mkdocs  
```bash
pip install mkdocs
$ mkdocs --version
mkdocs, version 0.15.3
```

# 创建项目

```bash
mkdocs new my-project
cd my-project
$ mkdocs serve  #启动服务器
```

# 目录组织方式

```yaml
mkdocs.yml  #配置nav菜单，默认所有目录按字母排序
docs/
    index.md  #会被渲染为index.html，也可用README.md代替
```

# 导航配置示例

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

# 更换主题

```bash
pip install mkdocs-material
```

修改配置  
```yaml
theme:
  name: 'material'
```

# MD语法

可使用相对路径和锚点指向header

## YAML Style Meta-Data

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

# 构建

```bash
mkdocs build  # 生成site目录
echo "site/" >> .gitignore  # 忽略site文件夹提交
mkdocs build --clean  # 清理目录
```

# 部署

## 分支部署

```bash
mkdocs gh-deploy  # 新建gh-pages分支
```

## 单独仓部署

```bash
cd ../orgname.github.io/  # 切换到仓目录
mkdocs gh-deploy --config-file ../my-project/mkdocs.yml --remote-branch master
```


# 参考链接：

- CTF WIKI: <https://ctf-wiki.github.io/ctf-wiki/>
- 官方网站：<https://www.mkdocs.org/>
- 主题：<https://squidfunk.github.io/mkdocs-material/>
