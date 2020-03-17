# 0x03_binary_search_tree

## 树

由N个节点和N-1条边组成

> 典型应用: Unix操作系统目录

### 遍历

- 先序、中序、后序其实指的是 **父节点** 被访问的次序。
- 不论是先序、中序、后序遍历, 左右孩子节点的相对访问次序不变

#### 先序遍历

```java
import java.util.Stack;

/**
 * 二叉树
 *               1
 *             /   \
 *            2     3
 *          /  \   / \
 *         4   5  6   7
 *           /     \
 *          8       9
 *
 * @since 2020-03-16
 */
public class BinTreeNode {
    // 数据域
    int val;
    // 左孩子
    BinTreeNode left;
    // 右孩子
    BinTreeNode right;
    // 父节点
    BinTreeNode parent;

    BinTreeNode(int x) {
        val = x;
    }

    /**
     * 先序遍历(递归)
     *
     * @param node
     */
    public static void preTravelRecursive(BinTreeNode node) {
        // 跳出语句
        if (node == null) {
            return;
        }
        // 先访问根节点
        System.out.println(node.val);

        // 再访问左右孩子
        preTravelRecursive(node.left);
        preTravelRecursive(node.right);
    }

    /**
     * 先序遍历(迭代)
     *
     * @param node
     */
    public static void preTravelIterate(BinTreeNode node) {
        Stack<BinTreeNode> stack = new Stack<>();
        // 先将根节点入栈
        if (node != null) {
            stack.push(node);
        }

        // 栈非空
        while (!stack.isEmpty()) {
            BinTreeNode top = stack.pop();
            System.out.println(top.val);

            // 先将右孩子入栈
            if (top.right != null) {
                stack.push(top.right);
            }

            if (top.left != null) {
                stack.push(top.left);
            }
        }
    }

    public static void main(String[] args) {
        BinTreeNode tn1 = new BinTreeNode(1);
        BinTreeNode tn2 = new BinTreeNode(2);
        BinTreeNode tn3 = new BinTreeNode(3);
        tn1.left = tn2;
        tn1.right = tn3;
        tn2.parent = tn1;
        tn3.parent = tn1;
        BinTreeNode tn4 = new BinTreeNode(4);
        BinTreeNode tn5 = new BinTreeNode(5);
        tn2.left = tn4;
        tn2.right = tn5;
        tn4.parent = tn2;
        tn5.parent = tn2;
        BinTreeNode tn6 = new BinTreeNode(6);
        BinTreeNode tn7 = new BinTreeNode(7);
        tn3.left = tn6;
        tn3.right = tn7;
        tn6.parent = tn3;
        tn7.parent = tn3;
        BinTreeNode tn8 = new BinTreeNode(8);
        BinTreeNode tn9 = new BinTreeNode(9);
        tn5.left = tn8;
        tn6.right = tn9;
        tn8.parent = tn5;
        tn9.parent = tn6;

        System.out.println("preTravelRecursive:");
        preTravelRecursive(tn1);
        System.out.println("preTravelIterate:");
        preTravelIterate(tn1);
    }
}
```

#### 中序遍历

#### 后序遍历

#### 层次遍历


!!! quote "参考链接: [二叉树的遍历详解](https://mp.weixin.qq.com/s/5yM7viuv6atoUsSvrrjGyQ)"


## 二叉查找树

- 左子树所有结点小于等于根结点
- 右子树所有结点大于等于根结点

在乱序的情况下使用二分法查找，所需查找的最大次数等于二叉树的高度。

在插入和删除元素的时候，无需插入后再对数组排序。

- 平均情况下时间复杂度O(logn)
- 在不平衡的最坏情况下时间复杂度为O(n)
