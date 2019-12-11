# Hashtable

!!! note "与HashMap的区别"
    1. Hashtable是同步访问的, {==线程安全==}

```java tab="函数原型"
import java.util.Hashtable;

public class Hashtable<K,V>
    extends Dictionary<K,V>
    implements Map<K,V>
```

```java tab="代码示例"
import java.util.Enumeration;
import java.util.Hashtable;

public class HashtableDemo {

    public static void main(String args[]) {
        Hashtable h = new Hashtable();
        h.put("apple", 1.5);
        h.put("banana", 2.7);

        Enumeration keys = h.keys();
        while (keys.hasMoreElements()) {
            String key = (String) keys.nextElement();
            System.out.println(h.get(key));
        }
    }
}
```
