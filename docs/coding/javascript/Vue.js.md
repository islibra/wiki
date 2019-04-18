---
title: Vue.js
date: 2018-09-08 11:33:44
categories: javascript
tags:
---

# 下载地址

[开发版本](https://vuejs.org/js/vue.js)
[生产版本](https://vuejs.org/js/vue.min.js)


# Hello Vue.js

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vue Demo</title>
<!-- 引入库 -->
<script src="vue.js"></script>
</head>
<body>
<div id="app">
  {{ message }}
</div>

<script>
var app = new Vue({
  el: '#app',
  data: {
    message: 'Hello Vue!'
  }
})
</script>
</body>
</html>
```


# 自定义指令

```html
  <span v-bind:title="message">
    鼠标悬停几秒钟查看此处动态绑定的提示信息！
  </span>
```


> 基于Vue.js的UI库：[iView](http://v2.iviewui.com/docs/guide/start)
