# Set

```java
import java.util.HashSet;
import java.util.Set;

public class SetDemo {

    public static void main(String[] args) {
        Set<String> result = new HashSet<>();
        Set<String> set1 = new HashSet<>();
        set1.add("a");
        set1.add("b");
        set1.add("c");
        Set<String> set2 = new HashSet<>();
        set2.add("b");
        set2.add("c");
        set2.add("d");

        // 交集
        result.clear();
        result.addAll(set1);
        result.retainAll(set2);
        System.out.println("交集: " + result);

        // 并集
        result.clear();
        result.addAll(set1);
        result.addAll(set2);
        System.out.println("并集: " + result);

        // 差集
        result.clear();
        result.addAll(set1);
        result.removeAll(set2);
        System.out.println("差集: " + result);
    }
}
```
