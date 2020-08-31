# 0xFB_单元测试

## JUnit 5

<https://junit.org/junit5/>

JUnit 5 由三个模块组成

1. JUnit Platform
1. JUnit Jupiter: 提供 Test 和 Assert API
1. Junit Vintage: 用于运行 JUnit 4 的测试

### 依赖

```xml
<dependencies>
    <dependency>
        <groupId>org.mockito</groupId>
        <artifactId>mockito-core</artifactId>
        <version>3.3.3</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.assertj</groupId>
        <artifactId>assertj-core</artifactId>
        <version>3.16.1</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter-api</artifactId>
        <version>5.6.2</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter-engine</artifactId>
        <version>5.6.2</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter-params</artifactId>
        <version>5.6.2</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.junit.platform</groupId>
        <artifactId>junit-platform-launcher</artifactId>
        <version>1.6.2</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

### demo

```java
import static org.junit.jupiter.api.Assertions.assertEquals;

import example.util.Calculator;

import org.junit.jupiter.api.Test;

class MyFirstJUnitJupiterTests {

    private final Calculator calculator = new Calculator();

    @Test
    void addition() {
        assertEquals(2, calculator.add(1, 1));
    }

}
```

### 断言

- assertEquals​(int expected, int actual)
- assertEquals​(Object expected, Object actual)
- assertTrue​(boolean condition)
- assertThrows​(Class<T> expectedType, Executable executable)
- assertEquals("/ by zero", exception.getMessage())

参考: <https://junit.org/junit5/docs/current/api/org.junit.jupiter.api/org/junit/jupiter/api/Assertions.html>

```java
import static java.time.Duration.ofMillis;
import static java.time.Duration.ofMinutes;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;

import example.domain.Person;
import example.util.Calculator;

import org.junit.jupiter.api.Test;

class AssertionsDemo {

    private final Calculator calculator = new Calculator();

    private final Person person = new Person("Jane", "Doe");

    @Test
    void standardAssertions() {
        assertEquals(2, calculator.add(1, 1));
        assertEquals(4, calculator.multiply(2, 2),
                "The optional failure message is now the last parameter");
        assertTrue('a' < 'b', () -> "Assertion messages can be lazily evaluated -- "
                + "to avoid constructing complex messages unnecessarily.");
    }

    @Test
    void groupedAssertions() {
        // In a grouped assertion all assertions are executed, and all
        // failures will be reported together.
        assertAll("person",
            () -> assertEquals("Jane", person.getFirstName()),
            () -> assertEquals("Doe", person.getLastName())
        );
    }

    @Test
    void dependentAssertions() {
        // Within a code block, if an assertion fails the
        // subsequent code in the same block will be skipped.
        assertAll("properties",
            () -> {
                String firstName = person.getFirstName();
                assertNotNull(firstName);

                // Executed only if the previous assertion is valid.
                assertAll("first name",
                    () -> assertTrue(firstName.startsWith("J")),
                    () -> assertTrue(firstName.endsWith("e"))
                );
            },
            () -> {
                // Grouped assertion, so processed independently
                // of results of first name assertions.
                String lastName = person.getLastName();
                assertNotNull(lastName);

                // Executed only if the previous assertion is valid.
                assertAll("last name",
                    () -> assertTrue(lastName.startsWith("D")),
                    () -> assertTrue(lastName.endsWith("e"))
                );
            }
        );
    }

    @Test
    void exceptionTesting() {
        Exception exception = assertThrows(ArithmeticException.class, () ->
            calculator.divide(1, 0));
        assertEquals("/ by zero", exception.getMessage());
    }

    @Test
    void timeoutNotExceeded() {
        // The following assertion succeeds.
        assertTimeout(ofMinutes(2), () -> {
            // Perform task that takes less than 2 minutes.
        });
    }

    @Test
    void timeoutNotExceededWithResult() {
        // The following assertion succeeds, and returns the supplied object.
        String actualResult = assertTimeout(ofMinutes(2), () -> {
            return "a result";
        });
        assertEquals("a result", actualResult);
    }

    @Test
    void timeoutNotExceededWithMethod() {
        // The following assertion invokes a method reference and returns an object.
        String actualGreeting = assertTimeout(ofMinutes(2), AssertionsDemo::greeting);
        assertEquals("Hello, World!", actualGreeting);
    }

    @Test
    void timeoutExceeded() {
        // The following assertion fails with an error message similar to:
        // execution exceeded timeout of 10 ms by 91 ms
        assertTimeout(ofMillis(10), () -> {
            // Simulate task that takes more than 10 ms.
            Thread.sleep(100);
        });
    }

    @Test
    void timeoutExceededWithPreemptiveTermination() {
        // The following assertion fails with an error message similar to:
        // execution timed out after 10 ms
        assertTimeoutPreemptively(ofMillis(10), () -> {
            // Simulate task that takes more than 10 ms.
            new CountDownLatch(1).await();
        });
    }

    private static String greeting() {
        return "Hello, World!";
    }

}
```

!!! quote "[JUnit 5 User Guide](https://junit.org/junit5/docs/current/user-guide/)"

### 高级断言

```java
import static org.assertj.core.api.Assertions.assertThat;

String result = "";
assertThat(result).isEqualTo("hello assert!");
```

```java
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

assertThatExceptionOfType(XxxException.class).isThrownBy(()->new Demo());
```

### 参数化

```java
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@ParameterizedTest(name = "[{index}] {2}. 细节: given: {0} | then: {1}")
@CsvSource({
        "first input, first result, first description",
        "sec input, sec result, sec description",
})
public void foo(String input, String expect, String desc) {
    Demo demo = new Demo();
    String result = demo.getResult(input);
    assertThat(result).isEqualTo(expect);
}
```

```java
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.Arguments;

// 定义一个 public static 的同名方法
public static Stream<Arguments> foo() {
    return Stream.of(
        Arguments.of(new ArrayList<String>(),
            "first input",
            "first result",
            "first description"
        ),
        Arguments.of(new ArrayList<String>(),
            "sec input",
            "sec result",
            "sec description"
        ));
}

@ParameterizedTest(name = "[{index}] {3}. 细节: given input: {1}| then: {2}")
@MethodSource
public void foo(List<String> filters, String input, String expect, String desc) {
    Demo demo = new Demo(filters);
    String result = demo.getResult(input);
    assertThat(result).isEqualTo(expect);
}
```

### 架构测试

```xml
<dependency>
    <groupId>com.tngtech.archunit</groupId>
    <artifactId>archunit</artifactId>
    <version>0.13.1</version>
    <scope>test</scope>
</dependency>
```

```java
DescribedPredicate<JavaClass> andFullNameDescribedPredicate =
                HasName.AndFullName.Predicates.fullNameMatching("org.katas.refactoring.clean.arch.domain..*")
                        .forSubType();
        DescribedPredicate<JavaClass> notBeDepend = JavaClass.Predicates.implement(AggreationInner.class)
                .and(andFullNameDescribedPredicate);

        ArchRule rule = classes().that().doNotImplement(PersistentObject.class)
                .and().doNotImplement(AggregationRoot.class)
                .should(ArchConditions.not(ArchConditions.dependOnClassesThat(notBeDepend)));

        rule.check(classes);
```


# JUnit 4


## 添加Maven依赖到test scope

```xml
<dependency>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <version>4.12</version>
  <scope>test</scope>
</dependency>
```


## Demo

```java
//被测试类
public class Calculator {
  public int evaluate(String expression) {
    int sum = 0;
    for (String summand: expression.split("\\+"))
      sum += Integer.valueOf(summand);
    return sum;
  }
}

//测试类
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class CalculatorTest {
  @Test  //添加注解
  public void evaluatesExpression() {
    Calculator calculator = new Calculator();
    int sum = calculator.evaluate("1+2+3");
    assertEquals(6, sum);  //断言
  }
}
```


## 断言

参数列表（failure message, expected value, actual value）

+ assertArrayEquals 数组相等
+ assertEquals Object相等
+ assertTrue 值为true
+ assertFalse 值为false
+ assertNull 值为null
+ assertNotNull 不为null
+ assertSame Object是同一个对象
+ assertNotSame Object不是同一个对象
+ assertThat 条件判断

> + containsString 包含字符串
> + both().and() 条件与
> + either().or() 条件或
> + hasItems 包含项
> + everyItem 每一项都
> + equalTo 相等
> + startsWith 以...开头
> + allOf 条件全部
> + not 条件非
> + anyOf 条件或
> + sameInstance 相同实例

```java
import org.hamcrest.core.CombinableMatcher;
import org.junit.Test;

import java.util.Arrays;

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.both;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.everyItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class AssertTest {

    @Test
    public void testAssertArrayEquals() {
        byte[] expected = "trial".getBytes();
        byte[] actual = "trial".getBytes();
        assertArrayEquals("failure - byte arrays not same", expected, actual);
    }

    @Test
    public void testAssertEquals() {
        assertEquals("failure - strings are not equal", "text", "text");
    }

    @Test
    public void testAssertTrue() {
        assertTrue("failure - should be true", true);
    }

    @Test
    public void testAssertFalse() {
        assertFalse("failure - should be false", false);
    }

    @Test
    public void testAssertNull() {
        assertNull("should be null", null);
    }

    @Test
    public void testAssertNotNull() {
        assertNotNull("should not be null", new Object());
    }

    @Test
    public void testAssertSame() {
        Integer aNumber = Integer.valueOf(768);
        assertSame("should be same", aNumber, aNumber);
    }

    @Test
    public void testAssertNotSame() {
        assertNotSame("should not be same Object", new Object(), new Object());
    }

    // JUnit Matchers assertThat
    @Test
    public void testAssertThatBothContainsString() {
        assertThat("albumen", both(containsString("a")).and(containsString("b")));
    }

    @Test
    public void testAssertThatHasItems() {
        assertThat(Arrays.asList("one", "two", "three"), hasItems("one", "three"));
    }

    @Test
    public void testAssertThatEveryItemContainsString() {
        assertThat(Arrays.asList(new String[] { "fun", "ban", "net" }), everyItem(containsString("n")));
    }

    // Core Hamcrest Matchers with assertThat
    @Test
    public void testAssertThatHamcrestCoreMatchers() {
        assertThat("good", allOf(equalTo("good"), startsWith("good")));
        assertThat("good", not(allOf(equalTo("bad"), equalTo("good"))));
        assertThat("good", anyOf(equalTo("bad"), equalTo("good")));
        assertThat(7, not(CombinableMatcher.<Integer> either(equalTo(3)).or(equalTo(4))));
        assertThat(new Object(), not(sameInstance(new Object())));
    }

}
```


## 异常

### 注解属性

```java
@Test(expected = IndexOutOfBoundsException.class)
public void empty() {
     new ArrayList<Object>().get(0);
}
```

### Try/Catch

```java
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@Test
public void testExceptionMessage() {
    try {
        new ArrayList<Object>().get(0);
        fail("Expected an IndexOutOfBoundsException to be thrown");
    } catch (IndexOutOfBoundsException anIndexOutOfBoundsException) {
        assertThat(anIndexOutOfBoundsException.getMessage(), is("Index: 0, Size: 0"));
    }
}
```

### ExpectedException Rule

```java
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

@Rule
public ExpectedException thrown = ExpectedException.none();

@Test
public void shouldTestExceptionMessage() throws IndexOutOfBoundsException {
    List<Object> list = new ArrayList<Object>();

    thrown.expect(IndexOutOfBoundsException.class);
    thrown.expectMessage("Index: 0, Size: 0");
    //thrown.expectMessage(CoreMatchers.containsString("Size: 0"));
    //thrown.expectMessage(startsWith("some Message"));
    //thrown.expect(hasProperty("response", hasProperty("status", is(404))));
    list.get(0); // execution will never get past this line
}
```


## 忽略

```java
@Ignore("Test is ignored as a demonstration")
```


## 预置/后置

```java
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class FSTPropertiesUtilsTest {

    @BeforeClass
    public static void setUpClass() {
        System.out.println("@BeforeClass setUpClass");
    }

    @AfterClass
    public static void tearDownClass() {
        System.out.println("@AfterClass tearDownClass");
    }

    @Before
    public void setUp() {
        System.out.println("@Before setUp");
    }

    @After
    public void tearDown() {
        System.out.println("@After tearDown");
    }

    @Test
    public void test1() {
        System.out.println("@Test test1()");
    }

    @Test
    public void test2() {
        System.out.println("@Test test2()");
    }
}
```


# JMockit


## 添加Maven依赖到test scope

```xml
<dependency>
   <groupId>org.jmockit</groupId> <artifactId>jmockit</artifactId> <version>1.21</version>
   <scope>test</scope>
</dependency>
```
