# BFS

## 图

- 顶点vertice
- 边edge

使用 **散列表** 存储，key为所有顶点，value为该顶点所有邻居的 **数组**。

## 广度优先搜索

!!! abstract "breadth-first search(BFS), 解决 **无权图** 的最短路径问题, 计算A到B有几跳, **最少换乘**"

使用 **队列** 广度优先搜索，先将第一层放入队列，弹出第一个元素判断，再将该顶点所有邻居放入队列，若队列为空，即未找到元素。

- 记录已检查过的节点，判断之前校验是否已检查过, 防止出现环
- 每层分一个队列，以记录跳数
- 队列中的元素为链表，连接到起点

!!! note "时间复杂度为 **O(V+E)**"

```java
package search;

import java.util.LinkedList;
import java.util.Queue;

/**
 * 101. 对称二叉树
 *
 * 给定一个二叉树，检查它是否是镜像对称的。
 * 例如，二叉树 [1,2,2,3,4,4,3] 是对称的。
 *
 *     1
 *    / \
 *   2   2
 *  / \ / \
 * 3  4 4  3
 *
 * 但是下面这个 [1,2,2,null,3,null,3] 则不是镜像对称的:
 *
 *     1
 *    / \
 *   2   2
 *    \   \
 *    3    3
 *
 * [9,-42,-42,null,76,76,null,null,13,null,13] >> false
 *
 * 说明:
 * 如果你可以运用递归和迭代两种方法解决这个问题，会很加分。
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/symmetric-tree
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 */
public class SymmetricBinTree {

    public boolean isSymmetric(TreeNode root) {
        if (root == null) {
            return true;
        }
        // 方法一、递归
        // return isMirror(root.left, root.right);
        // 方法二、BFS
        // 将左右孩子加入队列
        Queue queue = new LinkedList();
        queue.add(root.left);
        queue.add(root.right);
        while (!queue.isEmpty()) {
            // 获取2个元素
            TreeNode f = (TreeNode) queue.poll();
            TreeNode s = (TreeNode) queue.poll();
            if (f == null && s == null) {
                continue;
            }
            if (f == null || s == null || f.val != s.val) {
                return false;
            }
            queue.offer(f.left);
            queue.offer(s.right);
            queue.offer(f.right);
            queue.offer(s.left);
        }
        return true;
    }

    public boolean isMirror(TreeNode left, TreeNode right) {
        if (left == null && right == null) {
            return true;
        }
        if (left == null || right == null) {
            return false;
        }
        return left.val == right.val && isMirror(left.left, right.right) && isMirror(left.right, right.left);
    }

    public static void main(String args[]) {
        TreeNode root = new TreeNode(1);
        root.left = new TreeNode(2);
        root.right = new TreeNode(2);
        root.left.left = new TreeNode(3);
        root.left.right = new TreeNode(4);
        root.right.left = new TreeNode(4);
        root.right.right = new TreeNode(3);
        SymmetricBinTree sbt = new SymmetricBinTree();
        System.out.println(sbt.isSymmetric(root));
    }
}
```
