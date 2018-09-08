---
title: Node.js
date: 2018-09-08 11:35:35
categories: javascript
tags:
---

Node.js是javascript的运行时，基于Chrome的V8引擎，可直接运行javascript代码。

[官方下载地址](http://nodejs.org/)

内容包含：

+ Node.js runtime(node.exe) javascript运行时环境
+ npm package manager npm包管理器


# 查看Node.js版本

```bash
node -v
```


# 交互式运行

```bash
$ node
> console.log('hello');
hello
```


# 运行javascript文件

```bash
$ node min.js
```


# 官方Demo，运行一个http server

```javascript
const http = require('http');  //载入Node.js模块

const hostname = '127.0.0.1';
const port = 3000;

//创建http服务器
const server = http.createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end('Hello World\n');
});

//监听并响应请求
server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
```


# 查看npm版本

```bash
$ npm -v
6.2.0
```


# npm设置/取消代理

```bash
npm config set proxy http://username:password@server:port
npm config set https-proxy http://username:password@server:port
npm config delete proxy
npm config delete https-proxy
npm config list
```


# 使用npm安装模块

```bash
#-g 全局安装
#代码中通过require('xxx')载入模块
#同样适用于升级npm版本，如npm install npm -g
npm install xxx -g
```

+ 本地安装：在当前目录新建./node_modules目录存放安装包，代码中通过require()载入模块。
+ 全局安装：安装包存放在/usr/local或node安装目录（C:\Users\xxx\AppData\Roaming\npm\node_modules\xxx），可直接在命令行使用。


# 查看已安装的模块

```bash
npm list -g
npm list xxx
```


# 卸载/更新/搜索模块

```bash
$ npm uninstall express
$ npm update express
$ npm search express
```


# 创建模块并发布

```bash
$ npm init
$ npm adduser
Username:
...
$ npm publish
```


# 使用淘宝镜像

```bash
$ npm install -g cnpm --registry=https://registry.npm.taobao.org
$ cnpm install [name]
```
