# recursive

## 递归

任何递归都可以与while循环相互转换

> 使用循环, 性能更高; 使用递归, 更容易理解

!!! danger "关键结构"
    1. 基线条件: {==跳出语句==}
    1. 递归条件: **修正参数(更小规模)** 并调用自己

```java
public class Factorial {

    public static int factorial(int i) {
        System.out.println(i);
        // 1. 基线条件: 跳出循环
        if (i == 1) {
            return 1;
        }
        // 2. 递归条件: 修正参数(更小规模), 调用自己
        else {
            return i * factorial(i - 1);
        }
    }

    public static void main(String args[]) {
        System.out.println(factorial(5));
    }
}
```

## LeetCode

```java
public class TreeNode {
    int val;
    TreeNode left;
    TreeNode right;

    TreeNode(int x) {
        val = x;
    }
}

/**
 * 687. 最长同值路径
 *
 * 给定一个二叉树，找到最长的路径，这个路径中的每个节点具有相同值。 这条路径可以经过也可以不经过根节点。
 * 注意：两个节点之间的路径长度由它们之间的边数表示。
 *
 * 示例 1:
 * 输入:
 *               5
 *              / \
 *             4   5
 *            / \   \
 *           1   1   5
 * 输出:
 * 2
 *
 * 示例 2:
 * 输入:
 *               1
 *              / \
 *             4   5
 *            / \   \
 *           4   4   5
 * 输出:
 * 2
 *
 * 示例 3:
 * 输入:
 *                 1
 *                / \
 *            null   1
 *                 /  \
 *               1     1
 *              / \   /
 *             1   1 1
 * 输出:
 * 4
 *
 * 注意: 给定的二叉树不超过10000个结点。 树的高度不超过1000。
 *
 * 链接：https://leetcode-cn.com/problems/longest-univalue-path
 */
public class LongestUnivaluePath {

    // 所有节点中最长的
    private int maxLen;

    /**
     * 对每个节点, 求左右子树中最长的路径
     *
     * @param node 节点
     * @return 左右子树中最长路径
     */
    public int longestPath(TreeNode node) {
        // 基线条件: 叶子节点
        if (node == null) {
            return 0;
        }
        int leftPath = 0, rightPath = 0;
        // 递归条件, 修正参数并调用自己
        int left = longestPath(node.left);
        int right = longestPath(node.right);
        // 如果该节点与子节点同值, Path + 1, 否则为0
        if (node.left != null && node.left.val == node.val) {
            leftPath = left + 1;
        }
        if (node.right != null && node.right.val == node.val) {
            rightPath = right + 1;
        }
        // 记录所有节点中最长的, 有可能为左右子树连在一起
        maxLen = Math.max(maxLen, leftPath + rightPath);
        // 返回左右子树中最长路径
        return Math.max(leftPath, rightPath);
    }

    public int longestUnivaluePath(TreeNode root) {
        maxLen = 0;
        longestPath(root);
        return maxLen;
    }

    public static void main(String args[]) {
        LongestUnivaluePath lup = new LongestUnivaluePath();

        TreeNode root = new TreeNode(5);
        root.left = new TreeNode(4);
        root.right = new TreeNode(5);
        root.left.left = new TreeNode(1);
        root.left.right = new TreeNode(1);
        root.right.right = new TreeNode(5);
        System.out.println(lup.longestUnivaluePath(root));

        TreeNode root2 = new TreeNode(1);
        root2.left = new TreeNode(4);
        root2.right = new TreeNode(5);
        root2.left.left = new TreeNode(4);
        root2.left.right = new TreeNode(4);
        root2.right.right = new TreeNode(5);
        System.out.println(lup.longestUnivaluePath(root2));

        TreeNode root3 = new TreeNode(1);
        root3.left = null;
        root3.right = new TreeNode(1);
        root3.right.left = new TreeNode(1);
        root3.right.right = new TreeNode(1);
        root3.right.left.left = new TreeNode(1);
        root3.right.left.right = new TreeNode(1);
        root3.right.right.left = new TreeNode(1);
        System.out.println(lup.longestUnivaluePath(root3));
    }
}
```
