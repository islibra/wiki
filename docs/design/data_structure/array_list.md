# array_list

## 数组

- 大小固定, 无法动态扩展(扩容)
- 无法在任意位置插入删除, 需移动后面所有元素, **顺序写O(n)**
- {==可直接读取修改指定索引的元素==}, **随机读O(1)**

!!! example "适用于查找排序"

## 链表

- 每个元素存储了下一个元素的地址, 增加了空间开销, 可{==动态扩展==}(扩容)
- {==可在任意位置插入删除==}, **随机写O(1)**
- 无法直接读取中间某个元素, 查找时需要遍历整个链表, **顺序读O(n)**

!!! example "适用于实现队列"

- 单向链表
- 双向链表
- 循环链表
- 十字链表


## LeetCode

### 1. 两数之和

```java
import java.util.Arrays;
import java.util.Scanner;

/**
 * 1. 两数之和
 * 给定一个整数数组 nums 和一个目标值 target，请你在该数组中找出和为目标值的那 两个 整数，并返回他们的数组下标。
 * 你可以假设每种输入只会对应一个答案。但是，你不能重复利用这个数组中同样的元素。
 *
 * 示例:
 * 给定 nums = [2, 7, 11, 15], target = 9
 * 因为 nums[0] + nums[1] = 2 + 7 = 9
 * 所以返回 [0, 1]
 *
 * 链接：https://leetcode-cn.com/problems/two-sum
 */
public class TwoSum {

    public int[] twoSum(int[] nums, int target) {
        int[] result = new int[2];
        for (int i = 0; i < nums.length - 1; i++) {
            for (int j = i + 1; j < nums.length; j++) {
                if (nums[j] == target - nums[i]) {
                    result[0] = i;
                    result[1] = j;
                    return result;
                }
            }
        }
        return result;
    }

    public static void main(String args[]) {
        Scanner cin = new Scanner(System.in, "utf-8");
        String[] input = cin.nextLine().split(",");
        int len = input.length;
        int[] nums = new int[len];
        for (int i = 0; i < len; i++) {
            nums[i] = Integer.parseInt(input[i]);
        }

        int target = Integer.parseInt(cin.nextLine());

        TwoSum ts = new TwoSum();
        System.out.println(Arrays.toString(ts.twoSum(nums, target)));
    }
}
```

### 2. 两数相加

```java
import java.util.Scanner;

/**
 * 2. 两数相加
 * 给出两个 非空 的链表用来表示两个非负的整数。
 * 其中，它们各自的位数是按照 逆序 的方式存储的，并且它们的每个节点只能存储 一位 数字。
 * 如果，我们将这两个数相加起来，则会返回一个新的链表来表示它们的和。
 * 您可以假设除了数字 0 之外，这两个数都不会以 0 开头。
 *
 * 示例：
 * 输入：(2 -> 4 -> 3) + (5 -> 6 -> 4)
 * 输出：7 -> 0 -> 8
 * 原因：342 + 465 = 807
 *
 * 链接：https://leetcode-cn.com/problems/add-two-numbers
 */
public class TwoPlus {

    public ListNode addTwoNumbers(ListNode l1, ListNode l2) {
        ListNode result = null;
        ListNode rflag = null;
        // 进位标识
        int flag = 0;

        while (l1 != null && l2 != null) {
            int sum = l1.val + l2.val + flag;
            if (sum > 9) {
                flag = 1;
                sum -= 10;
            } else {
                flag = 0;
            }
            ListNode l = new ListNode(sum);
            if (result == null) {
                result = l;
                rflag = l;
            } else {
                // 追加
                rflag.next = l;
                // 移动指针
                rflag = l;
            }
            // 下一位
            l1 = l1.next;
            l2 = l2.next;
        }

        // 如果进位已经为0, 则直接将后面的位连到结果链表上
        if (flag == 0) {
            if (l1 != null) {
                rflag.next = l1;
            }
            if (l2 != null) {
                rflag.next = l2;
            }
        } else if (flag == 1) {
            while (l1 != null) {
                int sum = l1.val + flag;
                if (sum > 9) {
                    flag = 1;
                    sum -= 10;
                } else {
                    flag = 0;
                }
                ListNode l = new ListNode(sum);
                rflag.next = l;
                rflag = l;
                l1 = l1.next;
            }
            while (l2 != null) {
                int sum = l2.val + flag;
                if (sum > 9) {
                    flag = 1;
                    sum -= 10;
                } else {
                    flag = 0;
                }
                ListNode l = new ListNode(sum);
                rflag.next = l;
                rflag = l;
                l2 = l2.next;
            }
        }

        // 进位不为0
        if (flag == 1) {
            ListNode l = new ListNode(1);
            rflag.next = l;
        }

        return result;
    }

    public static void main(String args[]) {
        ListNode first = null;
        ListNode fflag = null;
        System.out.println("first:");
        Scanner cinone = new Scanner(System.in, "utf-8");
        while (cinone.hasNextInt()) {
            int one = cinone.nextInt();
            ListNode ln = new ListNode(one);
            if (first == null) {
                first = ln;
                fflag = first;
            } else {
                fflag.next = ln;
                fflag = ln;
            }
        }

        ListNode second = null;
        ListNode sflag = null;
        System.out.println("second:");
        Scanner cintwo = new Scanner(System.in, "utf-8");
        while (cintwo.hasNextInt()) {
            int two = cintwo.nextInt();
            ListNode ln = new ListNode(two);
            if (second == null) {
                second = ln;
                sflag = second;
            } else {
                sflag.next = ln;
                sflag = ln;
            }
        }

        TwoPlus tp = new TwoPlus();
        tp.printList(first);
        tp.printList(second);
        ListNode result = tp.addTwoNumbers(first, second);
        tp.printList(result);
    }

    public void printList(ListNode l) {
        while (l != null) {
            System.out.print(l.val + " -> ");
            l = l.next;
        }
        System.out.println();
    }
}

public class ListNode {
    int val;
    ListNode next;

    ListNode(int x) { val = x; }
}
```

### 19. 删除链表的倒数第N个节点

```java
/**
 * 链表节点
 *
 * @since 2020-03-12
 */
public class ListNode {
    int val;
    ListNode next;

    ListNode(int value) {
        val = value;
    }
}


/**
 * 19. 删除链表的倒数第N个节点
 * 给定一个链表，删除链表的倒数第 n 个节点，并且返回链表的头结点。
 *
 * 示例：
 * 给定一个链表: 1->2->3->4->5, 和 n = 2.
 * 当删除了倒数第二个节点后，链表变为 1->2->3->5.
 *
 * 说明：
 * 给定的 n 保证是有效的。
 *
 * 进阶：
 * 你能尝试使用一趟扫描实现吗？
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/remove-nth-node-from-end-of-list
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @since 2020-03-12
 */
public class RemoveNthFromEnd {
    /**
     * 删除链表的倒数第N个节点
     *
     * @param head 给定链表
     * @param n 倒数第n个节点
     * @return 结果链表首节点
     */
    public ListNode removeNthFromEnd(ListNode head, int n) {
        if (head == null) {
            return null;
        }
        ListNode current = head;
        for (int i = 0; i < n; i++) {
            current = current.next;
        }
        // 删除的是首节点
        if (current == null) {
            return head.next;
        }
        // 删除的是第二节点
        current = current.next;
        if (current == null) {
            head.next = head.next.next;
            return head;
        }
        ListNode nthFromEnd = head;
        while (current != null) {
            nthFromEnd = nthFromEnd.next;
            current = current.next;
        }
        nthFromEnd.next = nthFromEnd.next.next;
        return head;
    }

    /**
     * 打印链表
     *
     * @param list 被打印的链表
     */
    public void printList(ListNode list) {
        ListNode inputList = list;
        while (inputList != null) {
            System.out.print(inputList.val + " -> ");
            inputList = inputList.next;
        }
        System.out.println();
    }

    public static void main(String[] args) {
        ListNode first = new ListNode(1);
        ListNode second = new ListNode(2);
        first.next = second;
        ListNode third = new ListNode(3);
        second.next = third;
        ListNode fourth = new ListNode(4);
        third.next = fourth;
        ListNode fifth = new ListNode(5);
        fourth.next = fifth;

        RemoveNthFromEnd rnf = new RemoveNthFromEnd();
        rnf.printList(first);
        ListNode result = rnf.removeNthFromEnd(first, 2);
        rnf.printList(result);

        ListNode onlyone = new ListNode(1);
        rnf.printList(onlyone);
        ListNode rs = rnf.removeNthFromEnd(onlyone, 1);
        rnf.printList(rs);

        ListNode onlytwo = new ListNode(1);
        ListNode onlytwo2 = new ListNode(2);
        onlytwo.next = onlytwo2;
        rnf.printList(onlytwo);
        ListNode r2 = rnf.removeNthFromEnd(onlytwo, 2);
        rnf.printList(r2);
    }
}
```
