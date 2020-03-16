# 0x01_stack_queue

## 栈

!!! abstract "LIFO: 后进先出"

### 基本操作

- 初始化
- 压入栈
- 弹出栈顶元素
- 查看栈顶元素
- 判空

!!! example "典型应用: 函数调用栈 --> 栈溢出"

```java
package structure;

import java.util.EmptyStackException;
import java.util.Stack;

/**
 * 20. 有效的括号
 * <p>
 * 给定一个只包括 '('，')'，'{'，'}'，'['，']' 的字符串，判断字符串是否有效。
 * 有效字符串需满足：
 * 左括号必须用相同类型的右括号闭合。
 * 左括号必须以正确的顺序闭合。
 * 注意空字符串可被认为是有效字符串。
 * <p>
 * 示例 1:
 * 输入: "()"
 * 输出: true
 * <p>
 * 示例 2:
 * 输入: "()[]{}"
 * 输出: true
 * <p>
 * 示例 3:
 * 输入: "(]"
 * 输出: false
 * <p>
 * 示例 4:
 * 输入: "([)]"
 * 输出: false
 * <p>
 * 示例 5:
 * 输入: "{[]}"
 * 输出: true
 * <p>
 * 示例 6:
 * 输入: "]"
 * 输出: false
 * <p>
 * 链接：https://leetcode-cn.com/problems/valid-parentheses
 */
public class ValidBrackets {

    public boolean isValid(String s) {
        Stack stack = new Stack();
        try {
            char[] cArray = s.toCharArray();
            for (char c : cArray) {
                if (c == '(' || c == '[' || c == '{') {
                    stack.push(c);
                } else if (c == ')') {
                    char top = (char) stack.pop();
                    if (top != '(') {
                        return false;
                    }
                } else if (c == ']') {
                    char top = (char) stack.pop();
                    if (top != '[') {
                        return false;
                    }
                } else if (c == '}') {
                    char top = (char) stack.pop();
                    if (top != '{') {
                        return false;
                    }
                } else {
                    continue;
                }
            }
        } catch (EmptyStackException e) {
            return false;
        }
        return stack.empty();
    }

    public static void main(String args[]) {
        ValidBrackets vb = new ValidBrackets();
        String s1 = "()";
        System.out.println(vb.isValid(s1));
        String s2 = "()[]{}";
        System.out.println(vb.isValid(s2));
        String s3 = "(]";
        System.out.println(vb.isValid(s3));
        String s4 = "([)]";
        System.out.println(vb.isValid(s4));
        String s5 = "{[]}";
        System.out.println(vb.isValid(s5));
        String s6 = "]";
        System.out.println(vb.isValid(s6));
    }
}
```

## 队列

```java
import java.util.Arrays;

/**
 * 622. 设计循环队列
 * 设计你的循环队列实现。
 * 循环队列是一种线性数据结构，其操作表现基于 FIFO（先进先出）原则并且队尾被连接在队首之后以形成一个循环。
 * 它也被称为“环形缓冲器”。
 * 循环队列的一个好处是我们可以利用这个队列之前用过的空间。
 * 在一个普通队列里，一旦一个队列满了，我们就不能插入下一个元素，即使在队列前面仍有空间。
 * 但是使用循环队列，我们能使用这些空间去存储新的值。
 *
 * 你的实现应该支持如下操作：
 * MyCircularQueue(k): 构造器，设置队列长度为 k 。
 * Front: 从队首获取元素。如果队列为空，返回 -1 。
 * Rear: 获取队尾元素。如果队列为空，返回 -1 。
 * enQueue(value): 向循环队列插入一个元素。如果成功插入则返回真。
 * deQueue(): 从循环队列中删除一个元素。如果成功删除则返回真。
 * isEmpty(): 检查循环队列是否为空。
 * isFull(): 检查循环队列是否已满。
 *  
 * 提示：
 * 所有的值都在 0 至 1000 的范围内；
 * 操作数将在 1 至 1000 的范围内；
 * 请不要使用内置的队列库。
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/design-circular-queue
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * Your MyCircularQueue object will be instantiated and called as such:
 * MyCircularQueue obj = new MyCircularQueue(k);
 * boolean param_1 = obj.enQueue(value);
 * boolean param_2 = obj.deQueue();
 * int param_3 = obj.Front();
 * int param_4 = obj.Rear();
 * boolean param_5 = obj.isEmpty();
 * boolean param_6 = obj.isFull();
 */
public class MyCircularQueue {

    // 循环队列
    private int[] queue;
    // 队列长度
    private int size;
    // 是否为空
    private boolean empty;
    // 是否已满
    private boolean full;
    // 队首
    private int front;
    // 队尾
    private int rear;

    /**
     * Initialize your data structure here. Set the size of the queue to be k.
     */
    public MyCircularQueue(int k) {
        size = k;
        queue = new int[k];
        Arrays.fill(queue, -1);
        empty = true;
        full = false;
        front = 0;
        rear = 0;
    }

    /**
     * Insert an element into the circular queue. Return true if the operation is successful.
     */
    public boolean enQueue(int value) {
        // 队列已满
        if (full) {
            return false;
        }
        queue[rear] = value;
        empty = false;
        rear = (rear + 1) % size;
        if (rear == front) {
            full = true;
        }
        System.out.println(Arrays.toString(queue));
        return true;
    }

    /**
     * Delete an element from the circular queue. Return true if the operation is successful.
     */
    public boolean deQueue() {
        // 队列为空
        if (empty) {
            return false;
        }
        queue[front] = -1;
        full = false;
        front = (front + 1) % size;
        if (rear == front) {
            empty = true;
        }
        System.out.println(Arrays.toString(queue));
        return true;
    }

    /**
     * Get the front item from the queue.
     */
    public int Front() {
        return queue[front];
    }

    /**
     * Get the last item from the queue.
     */
    public int Rear() {
        return queue[(rear + size - 1) % size];
    }

    /**
     * Checks whether the circular queue is empty or not.
     */
    public boolean isEmpty() {
        return empty;
    }

    /**
     * Checks whether the circular queue is full or not.
     */
    public boolean isFull() {
        return full;
    }

    public static void main(String args[]){
//        MyCircularQueue circularQueue = new MyCircularQueue(3); // 设置长度为 3
//        System.out.println(circularQueue.enQueue(1));  // 返回 true
//        System.out.println(circularQueue.enQueue(2));  // 返回 true
//        System.out.println(circularQueue.enQueue(3));  // 返回 true
//        System.out.println(circularQueue.enQueue(4));  // 返回 false，队列已满
//        System.out.println(circularQueue.Rear());  // 返回 3
//        System.out.println(circularQueue.isFull());  // 返回 true
//        System.out.println(circularQueue.deQueue());  // 返回 true
//        System.out.println(circularQueue.enQueue(4));  // 返回 true
//        System.out.println(circularQueue.Rear());  // 返回 4

        MyCircularQueue circularQueue = new MyCircularQueue(6);
        System.out.println(circularQueue.enQueue(6));  // 返回 true
        System.out.println(circularQueue.Rear());  // 返回 6
        System.out.println(circularQueue.Rear());  // 返回 6
        System.out.println(circularQueue.deQueue());  // 返回 true
        System.out.println(circularQueue.enQueue(5));  // 返回 true
        System.out.println(circularQueue.Rear());  // 返回 5
        System.out.println(circularQueue.deQueue());  // 返回 true
        System.out.println(circularQueue.Front());  // 返回 -1
        System.out.println(circularQueue.deQueue());  // 返回 false
        System.out.println(circularQueue.deQueue());  // 返回 false
        System.out.println(circularQueue.deQueue());  // 返回 false
    }
}
```
