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

???+ tip
    script放入外部文件, 在body内底部引用, 如: `<script src="personController.js"></script>`


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


## 过滤器

> 添加到表达式或指令中.

过滤器 | 描述
--- | ---
currency | 格式化数字为货币格式。
lowercase | 格式化字符串为小写。
uppercase | 格式化字符串为大写。
filter | 从数组项中选择一个子集。
orderBy | 根据某个表达式排列数组。

```html tab="currency"
<div ng-app="myApp" ng-controller="myCtrl">
    <input type="number" ng-model="quantity">
    <input type="number" ng-model="price">

    <p>总价 = {{ (quantity * price) | currency }}</p>
</div>
```

```html tab="orderBy"
<ul>
    <li ng-repeat="x in names | orderBy:'country'">
        {{ x.name + ', ' + x.country }}
    </li>
</ul>
<script>
$scope.names = [
    {
        "name": "Emil",
        "country": "India"
    }, {
        "name": "Tobias",
        "country": "China"
    }, {
        "name": "Linus",
        "country": "American"
    }];
</script>
```

```html tab="filter"
<p><input type="text" ng-model="filterStr"></p>
<ul>
    <li ng-repeat="x in names | filter:filterStr | orderBy:'country'">
        {{ (x.name | uppercase) + ', ' + x.country }}
    </li>
</ul>
<script>
$scope.names = [
    {
        "name": "Emil",
        "country": "India"
    }, {
        "name": "Tobias",
        "country": "China"
    }, {
        "name": "Linus",
        "country": "American"
    }];
</script>
```


## 自定义过滤器

```html
名: <input type="text" ng-model="firstName"><br>
姓: <input type="text" ng-model="lastName"><br>
姓名: {{(firstName | reverse) + " " + lastName}}<br>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope) {
    $scope.firstName= "John";
    $scope.lastName= "Doe";
});
app.filter('reverse', function() {  // 可以注入依赖
    return function(text) {
        return text.split("").reverse().join("");
    }
});
</script>
```


## service

> 通过参数传入controller.

```html tab="location"
<h1>{{myUrl}}</h1>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope, $location) {
    $scope.myUrl = $location.absUrl();
});
</script>
```

```html tab="http"
<h1>{{myWelcome}}</h1>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope, $http) {
    // 注意必须是同一个域下的资源才能访问成功
    $http.get("service.html").then(function (response) {
        $scope.myWelcome = response.data;
    });

    // 另一种写法
    $http({
        method: 'GET',
        url: 'service.html'
    }).then(function successCallback(response) {
        // service.html {"sites": "localhost"}
        $scope.myWelcome = response.data.sites;
    }, function errorCallback(response) {
        // 请求失败执行代码
    });
});
</script>
```

```html tab="timeout"
<h1>{{myUrl}}</h1>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope, $location, $timeout) {
    $scope.myUrl = $location.absUrl();
    $timeout(function () {
        $scope.myWelcome = "How are you today?";
    }, 2000);
});
</script>
```

```html tab="interval"
<h1>{{theTime}}</h1>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope, $interval) {
    $scope.theTime = new Date().toLocaleTimeString();
    $interval(function () {
        $scope.theTime = new Date().toLocaleTimeString();
    }, 1000);
});
</script>
```

- $http.get('/someUrl', config).then(successCallback, errorCallback);
- $http.post('/someUrl', data, config).then(successCallback, errorCallback);
- $http.head
- $http.put
- $http.delete
- $http.jsonp
- $http.patch

???+ tip "允许跨域请求访问"
    需要在响应头中添加客户端域名, 如:

    ```php tab="php"
    header('Access-Control-Allow-Origin:http://client.runoob.com');
    header('Access-Control-Allow-Origin:*');
    ```

## 自定义service

```javascript
app.service('hexafy', function() {
    this.myFunc = function (x) {
        return x.toString(16);
    }
});
app.controller('myCtrl', function($scope, hexafy) {
    $scope.myUrl = hexafy.myFunc(255);
});
```

在过滤器中使用

```html
<p>我的第一个表达式： {{ (5 + 5) | myFormat }}</p>
<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope) {
});
// 自定义service
app.service('hexafy', function() {
    this.myFunc = function (x) {
        return x.toString(16);
    }
});
// 自定义过滤器调用service
app.filter('myFormat',['hexafy', function(hexafy) {
    return function(x) {
        return hexafy.myFunc(x);
    };
}]);
</script>
```






利用数组和ng-options创建下拉列表
<div ng-app="myApp" ng-controller="myCtrl">

<select ng-init="selectedName = names[0]" ng-model="selectedName" ng-options="x for x in names">
</select>

</div>

<script>
var app = angular.module('myApp', []);
app.controller('myCtrl', function($scope) {
    $scope.names = ["Google", "Runoob", "Taobao"];
});
</script>


$scope.sites = [
    {site : "Google", url : "http://www.google.com"},
    {site : "Runoob", url : "http://www.runoob.com"},
    {site : "Taobao", url : "http://www.taobao.com"}
];
<select ng-model="selectedSite" ng-options="x.site for x in sites">
</select>

<h1>你选择的是: {{selectedSite.site}}</h1>
<p>网址为: {{selectedSite.url}}</p>

对象作为数据源
$scope.cars = {
car01 : {brand : "Ford", model : "Mustang", color : "red"},
car02 : {brand : "Fiat", model : "500", color : "white"},
car03 : {brand : "Volvo", model : "XC90", color : "black"}
};
<select ng-model="selectedCar" ng-options="y.brand for (x, y) in cars">
</select>




表格
<table>
  <tr ng-repeat="x in names">
<td>{{ $index + 1 }}</td>
    <td>{{ x.Name }}</td>
    <td>{{ x.Country }}</td>
  </tr>
</table>




<button ng-disabled="mySwitch">点我!</button>

<p ng-show="true">我是可见的。</p>
<p ng-hide="true">我是不可见的。</p>
<p ng-show="hour > 12">我是可见的。</p>


<button ng-click="count = count + 1">点我！</button>

<p>{{ count }}</p>


定义模块依赖关系
var app = angular.module("myApp", []);


表单验证
<form  ng-app="myApp"  ng-controller="validateCtrl"
name="myForm" novalidate>

<p>用户名:<br>
  <input type="text" name="user" ng-model="user" required>
  <span style="color:red" ng-show="myForm.user.$dirty && myForm.user.$invalid">
  <span ng-show="myForm.user.$error.required">用户名是必须的。</span>
  </span>
</p>

<p>邮箱:<br>
  <input type="email" name="email" ng-model="email" required>
  <span style="color:red" ng-show="myForm.email.$dirty && myForm.email.$invalid">
  <span ng-show="myForm.email.$error.required">邮箱是必须的。</span>
  <span ng-show="myForm.email.$error.email">非法的邮箱。</span>
  </span>
</p>

<p>
  <input type="submit"
  ng-disabled="myForm.user.$dirty && myForm.user.$invalid ||
  myForm.email.$dirty && myForm.email.$invalid">
</p>

</form>

属性描述
$dirty表单有填写记录
$valid字段内容合法的
$invalid字段内容是非法的
$pristine表单没有填写记录


API
API描述
angular.lowercase (<angular1.7）
angular.$$lowercase()（angular1.7+）转换字符串为小写
angular.uppercase() (<angular1.7）
angular.$$uppercase()（angular1.7+）转换字符串为大写
angular.isString()判断给定的对象是否为字符串，如果是返回 true。
angular.isNumber()判断给定的对象是否为数字，如果是返回 true。
app.controller('myCtrl', function($scope) {
    $scope.x1 = "RUNOOB";
    $scope.x2 = angular.$$lowercase($scope.x1);
});


监控模型变量
$scope.$watch('passw1',function() {$scope.test();});
$scope.test = function() {
...}


## 安全函数

- ensureSafeObject：检测对象是否为函数构造方法，窗口对象，DOM参数，对象构造方法
- ensureSafeMemberName：检测属性不包含__proto__
- ensureSafeFunction：确保函数不会调用应用或绑定函数构造方法

## sanitizer

客户端过滤器，在html代码中绑定ng-bing-html属性，添加要过滤的参数。
