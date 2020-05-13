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
     * 深度优先搜索DFS
     * 先序遍历(递归)
     *
     * @param node 根节点
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
     * 深度优先搜索DFS
     * 先序遍历(迭代)
     *
     * @param node 根节点
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

```java
/**
 * 广度优先搜索BFS
 * 层次遍历
 *
 * @param node 根节点
 */
public static void levelOrderTravel(BinTreeNode node) {
    Queue<BinTreeNode> queue = new LinkedList<>();
    // 先把根节点入队
    if (node != null) {
        queue.offer(node);
    }

    while (!queue.isEmpty()) {
        // 取出并访问队首节点
        BinTreeNode top = queue.poll();
        LOG.info("" + top.val);

        if (top.left != null) {
            queue.offer(top.left);
        }
        if (top.right != null) {
            queue.offer(top.right);
        }
    }
}
```

```java
/**
 * 102. 二叉树的层序遍历
 * 给你一个二叉树，请你返回其按 层序遍历 得到的节点值。 （即逐层地，从左到右访问所有节点）。
 *
 * 示例：
 * 二叉树：[3,9,20,null,null,15,7]
 *
 *     3
 *    / \
 *   9  20
 *     /  \
 *    15   7
 *
 * 返回其层次遍历结果：
 * [
 *   [3],
 *   [9,20],
 *   [15,7]
 * ]
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/binary-tree-level-order-traversal
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param root 根节点
 * @return 层序遍历结果
 */
public static List<List<Integer>> levelOrder(BinTreeNode root) {
    Queue<BinTreeNode> queue = new LinkedList<>();
    // 先把根节点入队
    if (root != null) {
        queue.offer(root);
    }

    List<List<Integer>> result = new LinkedList<>();
    while (!queue.isEmpty()) {
        // 记录该层节点数量
        int count = queue.size();
        List<Integer> nodes = new ArrayList<>();

        // 一次性处理该层所有节点
        for (int i = 0; i < count; i++) {
            // 取出并访问队首节点
            BinTreeNode top = queue.poll();
            nodes.add(top.val);

            if (top.left != null) {
                queue.offer(top.left);
            }
            if (top.right != null) {
                queue.offer(top.right);
            }
        }
        result.add(nodes);
    }
    return result;
}
```

!!! quote "参考链接"
    - [二叉树的遍历详解](https://mp.weixin.qq.com/s/5yM7viuv6atoUsSvrrjGyQ)
    - [LeetCode 例题精讲 | 13 BFS 的使用场景：层序遍历、最短路径问题](https://mp.weixin.qq.com/s/OoPmFiZ0VKTJ-wf7QEc7zA)


### 112. 路径总和

```java
/**
 * 112. 路径总和
 * 给定一个二叉树和一个目标和，判断该树中是否存在根节点到叶子节点的路径，这条路径上所有节点值相加等于目标和。
 * 说明: 叶子节点是指没有子节点的节点。
 *
 * 示例: 
 * 给定如下二叉树，以及目标和 sum = 22，
 *
 *               5
 *              / \
 *             4   8
 *            /   / \
 *           11  13  4
 *          /  \      \
 *         7    2      1
 * 返回 true, 因为存在目标和为 22 的根节点到叶子节点的路径 5->4->11->2。
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/path-sum
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param root 二叉树
 * @param sum 目标和
 * @return 是否存在
 */
public static boolean hasPathSum(BinTreeNode root, int sum) {
    if (root == null) {
        return false;
    }

    // 叶子结点
    if (root.left == null && root.right == null) {
        return sum == root.val;
    }

    int subsum = sum - root.val;
    return hasPathSum(root.left, subsum) || hasPathSum(root.right, subsum);
}
```

!!! tip "凡是题目描述里提到叶结点的，都需要显式判断叶结点，在叶结点处结束递归。"

!!! quote "参考链接: [LeetCode 例题精讲 | 02 Path Sum：二叉树的子问题划分](https://mp.weixin.qq.com/s?__biz=MzA5ODk3ODA4OQ==&mid=2648167032&idx=1&sn=5734e539c8b037faf649df21dce4578d&chksm=88aa223ebfddab28c17163d0f80d4f966a6cff87277bca354e3c5e7aac25486386aa77c1dd0d&token=1450614154&lang=zh_CN&scene=21#wechat_redirect)"


## 二叉查找树

- 左子树所有结点小于等于根结点
- 右子树所有结点大于等于根结点

在乱序的情况下使用二分法查找，所需查找的最大次数等于二叉树的高度。

在插入和删除元素的时候，无需插入后再对数组排序。

- 平均情况下时间复杂度O(logn)
- 在不平衡的最坏情况下时间复杂度为O(n)
