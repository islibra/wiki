# Queue

```java
public interface Queue<E>
extends Collection<E>
{}
```

```java
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Queue;

public class QueueDemo {

    public static void main(String args[]) {
        // LinkedList实现了Queue接口
        Queue queue = new LinkedList();
        // add抛出异常
        queue.add(1);
        // 失败时返回false
        queue.offer(2);
        queue.offer(3);
        System.out.println(queue);

        try {
            // 查看队头
            int i = (int) queue.element();
            System.out.println(i);
            // 删除队头
            queue.remove();
            System.out.println(queue);
        } catch (NoSuchElementException e) {
            System.out.println(e);
        }

        // 查看队头
        if (queue.peek() != null) {
            // 删除队头
            queue.poll();
            System.out.println(queue);
        }
    }
}
```
