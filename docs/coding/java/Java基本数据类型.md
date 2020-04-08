# Java基本数据类型

| 数据类型 | 字节数 | 位数 | 范围 | 备注 |
| --- | --- | --- | --- | --- |
| Byte | 1 | 8 | [-2^7, 2^7-1] | [-128, 127] |
| Short | 2 | 16 | [-2^15, 2^15-1] | [-32768, 32767] |
| Integer | 4 | 32 | [-2^31, 2^31-1] | [-2147483648, 2147483647] |
| Long | 8 | 64 | [-2^63, 2^63-1] | [-9223372036854775808, 9223372036854775807] |
| Float | 4 | 32 | --- | --- |
| Double | 8 | 64 | --- | --- |
| Character | 2 | 16 | ['\u0000', '\uFFFF'] | [0, 65535] |

```java
// 直接赋值1或"false"会产生编译错误
boolean isTrue = Boolean.valueOf("true");
// true
System.out.println(isTrue);
boolean isFalse = Boolean.valueOf("false");
// false
System.out.println(isFalse);

// 以ASCII码赋值
char a = 97;
char b = 0x62;
System.out.println(a + " " + b);

// float赋值, 常量后面加f, 否则为double
float ff = 10.1f;
System.out.println(ff);
```

## String

### 拼接

```java
int age = 18;
System.out.println("He is " + age);
```

```java
System.out.println(String.join(" / ", "S", "M", "L", "XL"));
```

```java
// 线程安全
StringBuffer sbu = new StringBuffer();
sbu.append("Wor");
sbu.append("ld");
System.out.println(sbu.toString());

// JDK5.0引入, 非线程安全
StringBuilder sb = new StringBuilder();
sb.append("Hel");
sb.append("lo");
System.out.println(sb.toString());
```

### 比较

```java
String h1 = "hello";
String h2 = "Hello";
// false
System.out.println(h1.equals(h2));
// true
System.out.println(h1.equalsIgnoreCase(h2));
```

```java
// 是否在同一位置
String s1 = "abcdef";
String s2 = "abc" + "def";
String s3 = "abc";
String s4 = "def";
String s5 = s3 + s4;
// true
System.out.println(s1 == s2);
// false
System.out.println(s2 == s5);
```

```java
// 判空
System.out.println(s1 == null);
System.out.println("".equals(s1));
System.out.println(s1.length() == 0);
```
