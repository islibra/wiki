---
title: angularjs
---

# 引入angularjs

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.7.8/angular.min.js"></script>
<body ng-app>
</body>
```

# 安全函数

- ensureSafeObject：检测对象是否为函数构造方法，窗口对象，DOM参数，对象构造方法
- ensureSafeMemberName：检测属性不包含__proto__
- ensureSafeFunction：确保函数不会调用应用或绑定函数构造方法

# sanitizer

客户端过滤器，在html代码中绑定ng-bing-html属性，添加要过滤的参数。
