# Dijkstra

!!! abstract "寻找 **有向带权图** 的最短路径, **最短时间**"
    - 不适用于带 **环** 图
    - 不适用于 **负权** 图

## 思想

1. 使用二维散列表保存图中各节点的邻居和权重, 如

    ```
    Map m = HashMap() {
        "start": {
            "A": 6,
            "B": 2
        },
        "A": {
            "end": 1
        },
        "B": {
            "A": 3,
            "end": 5
        }
    }
    ```

1. 使用Map1保存起点到每个结点的开销，默认为无穷大, 如

    ```
    Map m1 = new HashMap() {
        "A": 6,
        "B": 2,
        "end": MAX
    }
    ```

1. 使用Map2保存每个节点的父节点, 如

    ```
    Map m2 = new HashMap() {
        "A": "start",
        "B": "start",
        "end": NULL
    }
    ```

1. 使用HashSet保存已处理过的节点
1. 循环, 在开销表中只要还有要处理的节点
    1. 找到起点到各节点的最短路径，刷新最短路径节点各邻居的开销和父节点。
1. 直到最短路径为终点

## 示例代码

```java
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

public class Dijkstra {

    private Set visited = new HashSet();

    public String findShortestPath(Map mcost) {
        int shortest = Integer.MAX_VALUE;
        String result = null;
        Set keys = mcost.keySet();
        for (Object key : keys) {
            if ((Integer) mcost.get(key) < shortest && !visited.contains(key)) {
                result = (String) key;
                shortest = (Integer) mcost.get(key);
            }
        }
        return result;
    }

    public Stack compute(Map m) {
        // 起点到其他各节点的开销
        Map mcost = new HashMap<String, Integer>();
        // 父节点
        Map parent = new HashMap<String, String>();

        Set nodes = m.keySet();
        for (Object o : nodes) {
            if (!"start".equals(o)) {
                mcost.put(o, Integer.MAX_VALUE);
                parent.put(o, "start");
            }
        }
        mcost.put("end", Integer.MAX_VALUE);
        parent.put("end", "start");
        Set startnodes = ((HashMap) m.get("start")).keySet();
        for (Object o : startnodes) {
            mcost.put(o, ((HashMap) m.get("start")).get(o));
        }

        // 在开销表中找到最短路径
        String key = findShortestPath(mcost);
        while (null != key && !"end".equals(key)) {
            // 更新其所有邻居及父节点
            Map mm = (HashMap) m.get(key);
            Set ss = mm.keySet();
            for (Object o : ss) {
                int newcost = (int) mcost.get(key) + (int) mm.get(o);
                if (newcost < (int) mcost.get(o)) {
                    mcost.put(o, newcost);
                    parent.put(o, key);
                }
            }
            visited.add(key);
            key = findShortestPath(mcost);
        }

        Stack stack = new Stack();
        String p = (String) parent.get("end");
        while (!"start".equals(p)) {
            stack.push(p);
            p = (String) parent.get(p);
        }
        System.out.println(mcost.get("end"));
        return stack;
    }

    public static void main(String[] args) {
        // 有向无权图
        Map mstart = new HashMap<String, Integer>();
        mstart.put("A", 6);
        mstart.put("B", 2);
        Map ma = new HashMap<String, Integer>();
        ma.put("end", 1);
        Map mb = new HashMap<String, Integer>();
        mb.put("A", 3);
        mb.put("end", 5);
        Map m = new HashMap<String, Map>();
        m.put("start", mstart);
        m.put("A", ma);
        m.put("B", mb);

        Dijkstra d = new Dijkstra();
        Stack s = d.compute(m);
        while (!s.empty()) {
            System.out.println(s.pop());
        }
    }
}
```
