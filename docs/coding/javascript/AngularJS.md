# AngularJS

官方网站:  
1.x: <https://angularjs.org/>  
latest: <https://angular.io/>

## 指令

> ng-directives，作为html元素的属性出现.

### ng-app

> 指明AngularJS应用.

### ng-model

> 把元素如input的值绑定到应用

???+ tip
    把脚本放在body内底部提升html加载速度.

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
</head>
<body>

<!-- 定义AngularJS应用 -->
<div ng-app="">
	<!-- 绑定html元素的值到应用 -->
    <p>名字 : <input type="text" ng-model="name"></p>
    <!-- 表达式输出 -->
    <h1>Hello {{name}}</h1>
</div>

<!-- js放在body内底部提升加载速度 -->
<script src="https://cdn.staticfile.org/angular.js/1.4.6/angular.min.js"></script>
</body>
</html>
```

#### 验证用户输入, 显示应用状态, 错误

```html
<div ng-app="" ng-init="myEmail = 'test@runoob.com'">
    <form name="myForm">
        Email:
        <input type="email" name="myAddress" ng-model="myEmail" required>
        <span ng-show="myForm.myAddress.$error.email">不是一个合法的邮箱地址</span>
        <h1>状态</h1>
        <h2>email格式错误$error.email: {{myForm.myAddress.$error.email}}</h2>
        <h2>表单校验正确$valid: {{myForm.myAddress.$valid}}</h2>
        <h2>修改过$dirty: {{myForm.myAddress.$dirty}}</h2>
        <h2>点击过$touched: {{myForm.myAddress.$touched}}</h2>
    </form>
</div>
```

### ng-bind

> 把应用数据绑定到视图.

### ng-init

> 初始化变量.

```html
<div ng-app="" ng-init="firstName='John'">
    <p>姓名为 <span ng-bind="firstName"></span></p>
</div>
```

### ng-repeat

> 重复元素.

```html
<div ng-app="" ng-init="firstName='John'; names=['Jani','Hege','Kai']">
    <p>姓名为 <span ng-bind="firstName"></span></p>

    <p>使用 ng-repeat 来循环数组</p>
	<ul>
    	<li ng-repeat="x in names">
    		{{ x }}
    	</li>
	</ul>
</div>
```

### ng-show


## 表达式

`{{exp}}` = ng-bind

> 可以包含运算符, 变量, 方法.

```html
<div ng-app="">
     <p>我的第一个表达式： {{ 5 + 5 }}</p>
</div>
```


## 控制器

> 在js中使用`module`声明应用，在应用中定义控制器

```html
<body>

<!-- 定义AngularJS应用 -->
<div ng-app="myApp" ng-controller="myCtrl">
    名: <input type="text" ng-model="firstName"><br>
    姓: <input type="text" ng-model="lastName"><br>
    <br>
    姓名: {{firstName + " " + lastName}}
</div>

<!-- js放在body内底部提升加载速度 -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.7.8/angular.min.js"></script>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope) {
    $scope.firstName= "John";
    $scope.lastName= "Doe";
});
</script>
</body>
```

### 在控制器中可定义方法改变属性值

```html
<body>

<!-- 定义AngularJS应用 -->
<div ng-app="myApp" ng-controller="myCtrl">
    <!-- 绑定模型 -->
    <p>名字 : <input type="text" ng-model="name"></p>
    <!-- 表达式输出 -->
    <h1>{{greeting}}</h1>
    <button ng-click='sayHello()'>点我</button>
</div>

<!-- js放在body内底部提升加载速度 -->
<script src="https://cdn.staticfile.org/angular.js/1.4.6/angular.min.js"></script>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope) {
    $scope.name = "Runoob";
    $scope.sayHello = function() {
        $scope.greeting = 'Hello ' + $scope.name + '!';
    };
});
</script>
</body>
```

## 作用域

在controller参数中添加`$scope`对应控制器, 添加`$rootScope`对应ng-app.

```html
<div ng-app="myApp" ng-controller="myCtrl">
    <h1>{{lastname}} 家族成员:</h1>
    <ul>
        <li ng-repeat="x in names">
            {{x}} {{lastname}}
        </li>
    </ul>
</div>

<!-- js放在body内底部提升加载速度 -->
<script src="https://cdn.staticfile.org/angular.js/1.4.6/angular.min.js"></script>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope, $rootScope) {
    $scope.names = ["Emil", "Tobias", "Linus"];
    $rootScope.lastname = "Refsnes";
});
</script>
```


## 自定义指令

> js中使用驼峰，html中使用中划线.

```html
<div ng-app="myApp">
    <runoob-directive></runoob-directive>
</div>
<script>
var app = angular.module('myApp', []);
app.directive("runoobDirective", function() {
    return {
        restrict : "EA",  // 限制调用方式
        template : "<h1>自定义指令!</h1>"
    };
});
</script>
```

### 调用方式

- 元素名E:

    ```html
    <runoob-directive></runoob-directive>
    ```

- 属性A:

    ```html
    <div runoob-directive></div>
    ```

- class C:

    ```html
    <div class="runoob-directive"></div>
    ```

- 注释M:

    ```html
    <!-- directive: runoob-directive -->
    ```


## 安全函数

- ensureSafeObject：检测对象是否为函数构造方法，窗口对象，DOM参数，对象构造方法
- ensureSafeMemberName：检测属性不包含__proto__
- ensureSafeFunction：确保函数不会调用应用或绑定函数构造方法

## sanitizer

客户端过滤器，在html代码中绑定ng-bing-html属性，添加要过滤的参数。
