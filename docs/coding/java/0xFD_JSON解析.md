# 0xFD_JSON解析

## j


## Jackson

<https://github.com/FasterXML/jackson>  
Java实现的JSON库，用来解析或生成JSON，和POJO互转，或其他格式如：Avro, BSON, CBOR, CSV, Smile, (Java) Properties, Protobuf, XML or YAML。

核心组件：
- jackson-core
- jackson-annotations
- jackson-databind

分支：
- 1.x 维护版本，[1.9.13](https://github.com/FasterXML/jackson/wiki/JacksonRelease1.9), released 14-Jul-2013, org.codehaus.jackson/jackson-mapper-asl  
- 2.x 开发版本，[2.9.7](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.9), released on 19-Sep-2018, com.fasterxml.jackson.core/jackson-databind

> **Tips:** 两个版本可同时依赖无冲突。

# 使用

1. 创建POJO  
```java
// Note: can use getters/setters as well; here we just use public fields directly:
public class MyValue {
  public String name;
  public int age;
  // NOTE: if using getters/setters, can keep fields `protected` or `private`
}
```
1. 创建`com.fasterxml.jackson.databind.ObjectMapper`实例  
```java
ObjectMapper mapper = new ObjectMapper(); // create once, reuse
```
1. 使用ObjectMapper读取JSON  
```java
MyValue value = mapper.readValue(new File("data.json"), MyValue.class);
// or:
value = mapper.readValue(new URL("http://some.com/api/entry.json"), MyValue.class);
// or:
value = mapper.readValue("{\"name\":\"Bob\", \"age\":13}", MyValue.class);
```
1. 将POJO格式化为JSON  
```java
mapper.writeValue(new File("result.json"), myResultObject);
// or:
byte[] jsonBytes = mapper.writeValueAsBytes(myResultObject);
// or:
String jsonString = mapper.writeValueAsString(myResultObject);
```
1. 使用`Map`, `List`进行读写  
```java
Map<String, Integer> scoreByName = mapper.readValue(jsonSource, Map.class);
List<String> names = mapper.readValue(jsonSource, List.class);

// and can obviously write out as well
mapper.writeValue(new File("names.json"), names);
```
1. 使用POJO作为`Map`, `List`的value  
```java
Map<String, ResultValue> results = mapper.readValue(jsonSource,
   new TypeReference<Map<String, ResultValue>>() { } );
// why extra work? Java Type Erasure will prevent type detection otherwise
```
1. 解析JSON tree  
```java
// can be read as generic JsonNode, if it can be Object or Array; or,
// if known to be Object, as ObjectNode, if array, ArrayNode etc:
ObjectNode root = mapper.readTree("stuff.json");
String name = root.get("name").asText();
int age = root.get("age").asInt();

// can modify as well: this adds child Object as property 'other', set property 'type'
root.with("other").put("type", "student");
String json = mapper.writeValueAsString(root);

// with above, we end up with something like as 'json' String:
// {
//   "name" : "Bob", "age" : 13,
//   "other" : {
//      "type" : "student"
//   }
// }
```
1. 通过流解析  
```java
JsonFactory f = mapper.getFactory(); // may alternatively construct directly too

// First: write simple JSON output
File jsonFile = new File("test.json");
JsonGenerator g = f.createGenerator(jsonFile);
// write JSON: { "message" : "Hello world!" }
g.writeStartObject();
g.writeStringField("message", "Hello world!");
g.writeEndObject();
g.close();

// Second: read file back
JsonParser p = f.createParser(jsonFile);

JsonToken t = p.nextToken(); // Should be JsonToken.START_OBJECT
t = p.nextToken(); // JsonToken.FIELD_NAME
if ((t != JsonToken.FIELD_NAME) || !"message".equals(p.getCurrentName())) {
   // handle error
}
t = p.nextToken();
if (t != JsonToken.VALUE_STRING) {
   // similarly
}
String msg = p.getText();
System.out.printf("My message to you is: %s!\n", msg);
p.close();
```
1. 将POJO通过JSON转换为另一个POJO  
```java
ResultType result = mapper.convertValue(sourceObject, ResultType.class);
// 例：
// Convert from List<Integer> to int[]
List<Integer> sourceList = ...;
int[] ints = mapper.convertValue(sourceList, int[].class);
// Convert a POJO into Map!
Map<String,Object> propertyMap = mapper.convertValue(pojoValue, Map.class);
// ... and back
PojoType pojo = mapper.convertValue(propertyMap, PojoType.class);
// decode Base64! (default byte[] representation is base64-encoded String)
String base64 = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz";
byte[] binary = mapper.convertValue(base64, byte[].class);
```

# 配置

```java
// higher-level
// SerializationFeature for changing how JSON is written

// to enable standard indentation ("pretty-printing"):
mapper.enable(SerializationFeature.INDENT_OUTPUT);
// to allow serialization of "empty" POJOs (no properties to serialize)
// (without this setting, an exception is thrown in those cases)
mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
// to write java.util.Date, Calendar as number (timestamp):
mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

// DeserializationFeature for changing how JSON is read as POJOs:

// to prevent exception when encountering unknown property:
mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
// to allow coercion of JSON empty String ("") to null Object value:
mapper.enable(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT);

// low-level
// JsonParser.Feature for configuring parsing settings:

// to allow C/C++ style comments in JSON (non-standard, disabled by default)
// (note: with Jackson 2.5, there is also `mapper.enable(feature)` / `mapper.disable(feature)`)
mapper.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
// to allow (non-standard) unquoted field names in JSON:
mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
// to allow use of apostrophes (single quotes), non standard
mapper.configure(JsonParser.Feature.ALLOW_SINGLE_QUOTES, true);

// JsonGenerator.Feature for configuring low-level JSON generation:

// to force escaping of non-ASCII characters:
mapper.configure(JsonGenerator.Feature.ESCAPE_NON_ASCII, true);
```

# 注解

## 修改POJO与JSON中映射的property名称

```java
public class MyBean {
   private String _name;

   // without annotation, we'd get "theName", but we want "name":
   @JsonProperty("name")
   public String getTheName() { return _name; }

   // note: it is enough to add annotation on just getter OR setter;
   // so we can omit it here
   public void setTheName(String n) { _name = n; }
}
```

## 忽略properties

```java
// means that if we see "foo" or "bar" in JSON, they will be quietly skipped
// regardless of whether POJO has such properties
@JsonIgnoreProperties({ "foo", "bar" })  //忽略多个
public class MyBean
{
   // will not be written as JSON; nor assigned from JSON:
   @JsonIgnore  //忽略单个
   public String internal;

   // no annotation, public field is read/written normally
   public String external;

   @JsonIgnore
   public void setCode(int c) { _code = c; }

   // note: will also be ignored because setter has annotation!
   public int getCode() { return _code; }
}
```

## 定义构造方法

```java
public class CtorBean
{
  public final String name;
  public final int age;

  @JsonCreator // constructor can be public, private, whatever
  private CtorBean(@JsonProperty("name") String name,
    @JsonProperty("age") int age)
  {
      this.name = name;
      this.age = age;
  }
}
// or:
public class FactoryBean
{
    // fields etc omitted for brewity

    @JsonCreator
    public static FactoryBean create(@JsonProperty("name") String name) {
      // construct and return an instance
    }
}
```


参考：[Jackson in N minutes](https://github.com/FasterXML/jackson-databind/)
