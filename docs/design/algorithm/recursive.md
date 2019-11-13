# recursive

## 递归

任何递归都可以与while循环相互转换

> 使用循环, 性能更高; 使用递归, 更容易理解

!!! danger "关键结构"
    1. 业务逻辑
    1. 基线条件: {==跳出语句==}
    1. 递归条件: **修正参数** 并调用自己

```java
public class Factorial {

    public static int factorial(int i) {
        // 1. 执行业务逻辑
        System.out.println(i);
        // 2. 基线条件: 跳出循环
        if (i == 1) {
            return 1;
        }
        // 3. 递归条件: 修正参数, 调用自己
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
 * <p>
 * 给定一个二叉树，找到最长的路径，这个路径中的每个节点具有相同值。 这条路径可以经过也可以不经过根节点。
 * 注意：两个节点之间的路径长度由它们之间的边数表示。
 * <p>
 * 示例 1:
 * 输入:
 * 5
 * / \
 * 4   5
 * / \   \
 * 1   1   5
 * 输出:
 * 2
 * <p>
 * 示例 2:
 * 输入:
 * 1
 * / \
 * 4   5
 * / \   \
 * 4   4   5
 * 输出:
 * 2
 * <p>
 * 注意: 给定的二叉树不超过10000个结点。 树的高度不超过1000。
 * <p>
 * 链接：https://leetcode-cn.com/problems/longest-univalue-path
 */
public class LongestUnivaluePath {

    public static int longestUnivaluePath(TreeNode root) {
        if (root == null) {
            return 0;
        }

        if (root.left == null && root.right == null) {
            return 0;
        } else {
            int left = 0;
            if (root.left != null) {
                left = longestUnivaluePath(root.left);
                if (root.val == root.left.val) {
                    left++;
                }
            }
            int right = 0;
            if (root.right != null) {
                right = longestUnivaluePath(root.right);
                if (root.val == root.right.val) {
                    right++;
                }
            }
            if (root.left != null && root.right != null
                    && root.val == root.left.val && root.val == root.right.val) {
                return left + right;
            } else {
                return Math.max(left, right);
            }
        }
    }

    public static void main(String args[]) {
        TreeNode root = new TreeNode(5);
        root.left = new TreeNode(4);
        root.right = new TreeNode(5);
        root.left.left = new TreeNode(1);
        root.left.right = new TreeNode(1);
        root.right.right = new TreeNode(5);
        System.out.println(longestUnivaluePath(root));

        TreeNode root2 = new TreeNode(1);
        root2.left = new TreeNode(4);
        root2.right = new TreeNode(5);
        root2.left.left = new TreeNode(4);
        root2.left.right = new TreeNode(4);
        root2.right.right = new TreeNode(5);
        System.out.println(longestUnivaluePath(root2));
    }
}
```
