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

### 113. 路径总和 II

```java
/**
 * 113. 路径总和 II
 * 给定一个二叉树和一个目标和，找到所有从根节点到叶子节点路径总和等于给定目标和的路径。
 * 说明: 叶子节点是指没有子节点的节点。
 * 示例:
 * 给定如下二叉树，以及目标和 sum = 22，
 *
 *               5
 *              / \
 *             4   8
 *            /   / \
 *           11  13  4
 *          /  \    / \
 *         7    2  5   1
 * 返回:
 * [
 *    [5,4,11,2],
 *    [5,8,4,5]
 * ]
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/path-sum-ii
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param root 二叉树
 * @param sum 目标路径总和
 * @return 符合条件的路径列表
 */
public static List<List<Integer>> pathSum(BinTreeNode root, int sum) {
    List<List<Integer>> result = new LinkedList<>();
    // 使用回溯法先初始化一个存放路径的栈
    Stack<Integer> path = new Stack<>();
    dfsFindPath(root, path, sum, result);
    return result;
}

// DFS寻找符合目标和的路径, 加入到结果列表中
private static void dfsFindPath(BinTreeNode node, Stack<Integer> path, int sum,
        List<List<Integer>> result) {
    // 跳出语句
    if (node == null) {
        return;
    }

    path.push(node.val);
    // 叶子结点
    if (node.left == null && node.right == null) {
        // 计算路径和
        int pathSum = 0;
        for (int i : path) {
            pathSum += i;
        }
        if (sum == pathSum) {
            List<Integer> copy = new Stack<>();
            copy.addAll(path);
            result.add(copy);
        }
    }

    // 再访问左右孩子
    dfsFindPath(node.left, path, sum, result);
    dfsFindPath(node.right, path, sum, result);

    // 回溯的时候将结点出栈
    path.pop();
}
```

### 78. 子集

```java
/**
 * 78. 子集
 * 给定一组不含重复元素的整数数组 nums，返回该数组所有可能的子集（幂集）。
 * 说明：解集不能包含重复的子集。
 * 示例:
 * 输入: nums = [1,2,3]
 * 输出:
 * [
 *   [3],
 *   [1],
 *   [2],
 *   [1,2,3],
 *   [1,3],
 *   [2,3],
 *   [1,2],
 *   []
 * ]
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/subsets
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param nums 数组
 * @return 子集列表
 */
public static List<List<Integer>> subsets(int[] nums) {
    List<List<Integer>> result = new LinkedList<>();
    Stack<Integer> subset = new Stack<>();
    backtrack(nums, 0, subset, result);
    return result;
}

private static void backtrack(int[] nums, int level, Stack<Integer> subset,
        List<List<Integer>> result) {
    // 在叶子节点处退出
    if (level == nums.length) {
        List<Integer> copy = new Stack<>();
        copy.addAll(subset);
        result.add(copy);

        return;
    }

    // 选择
    subset.push(nums[level]);
    backtrack(nums, level + 1, subset, result);
    // 不选
    subset.pop();
    backtrack(nums, level + 1, subset, result);
}
```

!!! quote "参考链接: [LeetCode 例题精讲 | 03 从二叉树遍历到回溯算法](https://mp.weixin.qq.com/s?__biz=MzA5ODk3ODA4OQ==&mid=2648167045&idx=1&sn=55577c31fd264a13511b4c0f27b3acce&chksm=88aa22c3bfddabd58c470f2933d6272c37f2d6d7a25ddda93f7203a25bf8bc8be4a15e8b9eb4&token=1450614154&lang=zh_CN&scene=21#wechat_redirect)"

### 543. 二叉树的直径

```java
/**
 * 543. 二叉树的直径
 * 给定一棵二叉树，你需要计算它的直径长度。一棵二叉树的直径长度是任意两个结点路径长度中的最大值。这条路径可能穿过也可能不穿过根结点。
 * 示例 :
 * 给定二叉树
 *
 *           1
 *          / \
 *         2   3
 *        / \
 *       4   5
 * 返回 3, 它的长度是路径 [4,2,1,3] 或者 [5,2,1,3]。
 * 注意：两结点之间的路径长度是以它们之间边的数目表示。
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/diameter-of-binary-tree
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param root 给定二叉树
 * @return 直径
 */
public static int diameterOfBinaryTree(BinTreeNode root) {
    return diameterAndMaxDeep(root)[0];
}

// 定义一个递归方法, 返回二叉树的直径和深度
private static int[] diameterAndMaxDeep(BinTreeNode root) {
    if (root == null) {
        return new int[]{0, 0};
    }

    int[] left = diameterAndMaxDeep(root.left);
    int[] right = diameterAndMaxDeep(root.right);
    // 左子树或右子树的直径较大者
    // 这里的直径也可以定义为全局变量
    int diameter = Math.max(left[0], right[0]);
    // 再与经过当前节点的路径比较
    int leftDeep = root.left == null ? 0 : 1;
    int rightDeep = root.right == null ? 0 : 1;
    // 左子树的深度 + 右子树的深度 + 左右子树到当前节点的路径
    diameter = Math.max(diameter, left[1] + right[1] + leftDeep + rightDeep);

    // 当前节点的深度 = 左右子树的深度+1较大者
    return new int[]{
            diameter, Math.max(left[1] + leftDeep, right[1] + rightDeep)
    };
}
```

### 124. 二叉树中的最大路径和

```java
/**
 * 124. 二叉树中的最大路径和
 * 给定一个非空二叉树，返回其最大路径和。
 * 本题中，路径被定义为一条从树中任意节点出发，达到任意节点的序列。该路径至少包含一个节点，且不一定经过根节点。
 *
 * 示例 1:
 * 输入: [1,2,3]
 *
 *        1
 *       / \
 *      2   3
 *
 * 输出: 6
 *
 * 示例 2:
 * 输入: [-10,9,20,null,null,15,7]
 *
 *    -10
 *    / \
 *   9  20
 *     /  \
 *    15   7
 *
 * 输出: 42
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/binary-tree-maximum-path-sum
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param root 二叉树
 * @return 最大路径和
 */
public static int maxPathSum(BinTreeNode root) {
    // 节点有可能为负, 所以不能初始化为0
    maxSum = root.val;
    maxSingleSum(root);
    return maxSum;
}

public static int maxSum;

private static int maxSingleSum(BinTreeNode node) {
    if (node == null) {
        return 0;
    }
    // 如果子树的单侧最大和是负, 则不计算
    int left = Math.max(0, maxSingleSum(node.left));
    int right = Math.max(0, maxSingleSum(node.right));
    maxSum = Math.max(maxSum, left + node.val);
    maxSum = Math.max(maxSum, right + node.val);
    maxSum = Math.max(maxSum, left + right + node.val);
    return node.val + Math.max(left, right);
}
```

!!! quote "参考链接: [LeetCode 例题精讲 | 10 二叉树直径：二叉树遍历中的全局变量](https://mp.weixin.qq.com/s?__biz=MzA5ODk3ODA4OQ==&mid=2648167144&idx=1&sn=93a4dfaa42aa1bf78d121e224efb7adb&chksm=88aa22aebfddabb8ec6312c96e9178a96a80558ed1eaea89906c3e7c49899cde4b62fdeca7bf&token=621102215&lang=zh_CN&scene=21#wechat_redirect)"


## 二叉查找树

- 左子树所有结点小于等于根结点
- 右子树所有结点大于等于根结点

在乱序的情况下使用二分法查找，所需查找的最大次数等于二叉树的高度。

在插入和删除元素的时候，无需插入后再对数组排序。

- 平均情况下时间复杂度O(logn)
- 在不平衡的最坏情况下时间复杂度为O(n)
