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
