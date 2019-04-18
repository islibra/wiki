---
title: 使用Hexo搭建个人博客
date: 2018-07-14 12:48:57
categories: writing
tags:
---

# 一、Git

+ 在GitHub注册个人账号，并跟随向导创建Repository。
+ 安装[Git](https://git-scm.com/download/win)。
+ 创建SSH KEY
```bash
git config --global user.name "username"
git config --global user.email "usermail"
git config --global --list
ssh-keygen -t rsa -C "usermail"  #在默认路径生成.ssh/id_rsa.pub，使用记事本打开并拷贝内容，添加到GitHub上的SSH and GPG keys里。
```

# 二、Node.js

[下载地址](http://nodejs.org/)

# 三、Hexo

```bash
npm install -g hexo-cli  #使用npm安装Hexo
hexo init <folder>  #初始化根目录
cd <folder>
npm install
npm install --save hexo-deployer-git  #安装Git部署服务
```

# 四、目录

> + _config.yml  网站配置
> + package.json  应用程序信息，如已安装的`hexo-deployer-git`
> + public/  存放生成的站点文件
> + scaffolds/  模板，创建新文章时默认填充
> + source/  存放Markdown源文件，被解析到public文件夹
> + themes/  主题

# 五、与GitHub Pages关联

编辑`_config.yml`文件，添加

```yaml
deploy:
  type: git
  repo: git@github.com:xxx.git
  branch: master
```

# 六、写作

```bash
hexo new "My New Post"
hexo server -p 5000
hexo generate
hexo deploy
hexo clean
```

# 七、主题

[NexT](https://github.com/iissnan/hexo-theme-next/releases)