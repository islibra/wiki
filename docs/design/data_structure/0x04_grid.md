# 0x04_grid

m x n, 每个方格与其上下左右四个方格相邻

每个格子中的数字可能是0或1, 1为不可达

## 基线条件

`(r,c)==null`

## 递归条件

对于`(r,c)`, 相邻节点`(r,c-1)`, `(r,c+1)`, `(r-1,c)`, `(r+1,c)`

## 重复节点

## DFS

```java
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * 深度优先搜索DFS遍历网格
 *
 * @since 2020-04-30
 */
public class Grid {
    private static final Logger LOG = Logger.getLogger(Grid.class.getName());

    public static void dfs(List<List<Integer>> grid, int r, int c) {
        if (!inArea(grid, r, c)) {
            return;
        }

        // 防止重复遍历
        List<Integer> row = grid.get(r);
        if (-1 == row.get(c)) {
            return;
        }
        // 访问节点
        LOG.info("" + row.get(c));
        // 标记已遍历过
        row.set(c, -1);
        grid.set(r, row);

        dfs(grid, r, c - 1);
        dfs(grid, r, c + 1);
        dfs(grid, r - 1, c);
        dfs(grid, r + 1, c);
    }

    // 基线条件
    private static boolean inArea(List<List<Integer>> grid, int r, int c) {
        int row_max = grid.size();
        int col_max = grid.get(0).size();
        return (0 <= r && r < row_max && 0 <= c && c < col_max);
    }

    public static void main(String[] args) {
        List<List<Integer>> grid = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            List<Integer> row = new ArrayList<>();
            for (int j = 0; j < 4; j++) {
                row.add(i * 4 + j);
            }
            grid.add(row);
        }
        LOG.info("" + grid);

        dfs(grid, 2, 3);
    }
}
```

```java
/**
 * 695. 岛屿的最大面积
 * 给定一个包含了一些 0 和 1 的非空二维数组 grid 。
 * 一个 岛屿 是由一些相邻的 1 (代表土地) 构成的组合，这里的「相邻」要求两个 1 必须在水平或者竖直方向上相邻。你可以假设 grid 的四个边缘都被
 * 0（代表水）包围着。
 * 找到给定的二维数组中最大的岛屿面积。(如果没有岛屿，则返回面积为 0 。)
 *
 * 示例 1:
 * [[0,0,1,0,0,0,0,1,0,0,0,0,0],
 *  [0,0,0,0,0,0,0,1,1,1,0,0,0],
 *  [0,1,1,0,1,0,0,0,0,0,0,0,0],
 *  [0,1,0,0,1,1,0,0,1,0,1,0,0],
 *  [0,1,0,0,1,1,0,0,1,1,1,0,0],
 *  [0,0,0,0,0,0,0,0,0,0,1,0,0],
 *  [0,0,0,0,0,0,0,1,1,1,0,0,0],
 *  [0,0,0,0,0,0,0,1,1,0,0,0,0]]
 * 对于上面这个给定矩阵应返回 6。注意答案不应该是 11 ，因为岛屿只能包含水平或垂直的四个方向的 1 。
 *
 * 示例 2:
 * [[0,0,0,0,0,0,0,0]]
 * 对于上面这个给定的矩阵, 返回 0。
 *
 * 注意: 给定的矩阵grid 的长度和宽度都不超过 50。
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/max-area-of-island
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 *
 * @param grid 网格地图
 * @return 最大的岛屿面积
 */
public static int maxAreaOfIsland(int[][] grid) {
    int maxArea = 0;
    for (int i = 0; i < grid.length; i++) {
        for (int j = 0; j < grid[0].length; j++) {
            int area = area(grid, i, j);
            maxArea = area > maxArea ? area : maxArea;
        }
    }
    return maxArea;
}

private static int area(int[][] grid, int r, int c) {
    if (!inGrid(grid, r, c)) {
        return 0;
    }

    // 防止重复遍历
    if (1 != grid[r][c]) {
        return 0;
    }

    // 标记已遍历过
    grid[r][c] = -1;

    return 1 + area(grid, r, c - 1) + area(grid, r, c + 1) + area(grid, r - 1, c)
            + area(grid, r + 1, c);
}

private static boolean inGrid(int[][] grid, int r, int c) {
    int row_max = grid.length;
    int col_max = grid[0].length;
    return (0 <= r && r < row_max && 0 <= c && c < col_max);
}

public static void main(String[] args) {
    int[][] grid = {
            {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0},
            {0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
            {0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0},
            {0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0},
            {0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0}
    };
    LOG.info("" + maxAreaOfIsland(grid));
}
```

```java
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 */

package structure;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Logger;

/**
 * 深度优先搜索DFS遍历网格
 *
 * @since 2020-04-30
 */
public class Grid {
    private static final Logger LOG = Logger.getLogger(Grid.class.getName());

    public static void dfs(List<List<Integer>> grid, int r, int c) {
        if (!inArea(grid, r, c)) {
            return;
        }

        // 防止重复遍历
        List<Integer> row = grid.get(r);
        if (-1 == row.get(c)) {
            return;
        }
        // 访问节点
        LOG.info("" + row.get(c));
        // 标记已遍历过
        row.set(c, -1);
        grid.set(r, row);

        dfs(grid, r, c - 1);
        dfs(grid, r, c + 1);
        dfs(grid, r - 1, c);
        dfs(grid, r + 1, c);
    }

    // 基线条件
    private static boolean inArea(List<List<Integer>> grid, int r, int c) {
        int row_max = grid.size();
        int col_max = grid.get(0).size();
        return (0 <= r && r < row_max && 0 <= c && c < col_max);
    }

    public static void basicTravel() {
        List<List<Integer>> grid = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            List<Integer> row = new ArrayList<>();
            for (int j = 0; j < 4; j++) {
                row.add(i * 4 + j);
            }
            grid.add(row);
        }
        LOG.info("" + grid);

        dfs(grid, 2, 3);
    }

    /**
     * 695. 岛屿的最大面积
     * 给定一个包含了一些 0 和 1 的非空二维数组 grid 。
     * 一个 岛屿 是由一些相邻的 1 (代表土地) 构成的组合，这里的「相邻」要求两个 1 必须在水平或者竖直方向上相邻。你可以假设 grid 的四个边缘都被
     * 0（代表水）包围着。
     * 找到给定的二维数组中最大的岛屿面积。(如果没有岛屿，则返回面积为 0 。)
     *
     * 示例 1:
     * [[0,0,1,0,0,0,0,1,0,0,0,0,0],
     *  [0,0,0,0,0,0,0,1,1,1,0,0,0],
     *  [0,1,1,0,1,0,0,0,0,0,0,0,0],
     *  [0,1,0,0,1,1,0,0,1,0,1,0,0],
     *  [0,1,0,0,1,1,0,0,1,1,1,0,0],
     *  [0,0,0,0,0,0,0,0,0,0,1,0,0],
     *  [0,0,0,0,0,0,0,1,1,1,0,0,0],
     *  [0,0,0,0,0,0,0,1,1,0,0,0,0]]
     * 对于上面这个给定矩阵应返回 6。注意答案不应该是 11 ，因为岛屿只能包含水平或垂直的四个方向的 1 。
     *
     * 示例 2:
     * [[0,0,0,0,0,0,0,0]]
     * 对于上面这个给定的矩阵, 返回 0。
     *
     * 注意: 给定的矩阵grid 的长度和宽度都不超过 50。
     *
     * 来源：力扣（LeetCode）
     * 链接：https://leetcode-cn.com/problems/max-area-of-island
     * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
     *
     * @param grid 网格地图
     * @return 最大的岛屿面积
     */
    public static int maxAreaOfIsland(int[][] grid) {
        int maxArea = 0;
        for (int i = 0; i < grid.length; i++) {
            for (int j = 0; j < grid[0].length; j++) {
                int area = area(grid, i, j);
                maxArea = area > maxArea ? area : maxArea;
            }
        }
        return maxArea;
    }

    private static int area(int[][] grid, int r, int c) {
        if (!inGrid(grid, r, c)) {
            return 0;
        }

        // 防止重复遍历
        if (1 != grid[r][c]) {
            return 0;
        }

        // 标记已遍历过
        grid[r][c] = -1;

        return 1 + area(grid, r, c - 1) + area(grid, r, c + 1) + area(grid, r - 1, c)
                + area(grid, r + 1, c);
    }

    private static boolean inGrid(int[][] grid, int r, int c) {
        int row_max = grid.length;
        int col_max = grid[0].length;
        return (0 <= r && r < row_max && 0 <= c && c < col_max);
    }

    /**
     * 827. 最大人工岛
     * 在二维地图上， 0代表海洋， 1代表陆地，我们最多只能将一格 0 海洋变成 1变成陆地。
     * 进行填海之后，地图上最大的岛屿面积是多少？（上、下、左、右四个方向相连的 1 可形成岛屿）
     *
     * 示例 1:
     * 输入: [[1, 0], [0, 1]]
     * 输出: 3
     * 解释: 将一格0变成1，最终连通两个小岛得到面积为 3 的岛屿。
     *
     * 示例 2:
     * 输入: [[1, 1], [1, 0]]
     * 输出: 4
     * 解释: 将一格0变成1，岛屿的面积扩大为 4。
     *
     * 示例 3:
     * 输入: [[1, 1], [1, 1]]
     * 输出: 4
     * 解释: 没有0可以让我们变成1，面积依然为 4。
     *
     * 说明:
     * 1 <= grid.length = grid[0].length <= 50
     * 0 <= grid[i][j] <= 1
     *
     * 来源：力扣（LeetCode）
     * 链接：https://leetcode-cn.com/problems/making-a-large-island
     * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
     *
     * @param grid 网格地图
     * @return 填海造陆后的最大岛屿面积
     */
    public static int largestIsland(int[][] grid) {
        int maxArea = 0;

        // 记录每个岛的面积
        Vector<Integer> areas = new Vector<>();
        // 从2开始标记
        int flag = 2;
        for (int i = 0; i < grid.length; i++) {
            for (int j = 0; j < grid[0].length; j++) {
                int area = areaFlag(grid, i, j, flag);
                if (0 != area) {
                    flag++;
                    areas.add(area);
                }
            }
        }

        // 遍历海洋
        int fixedI = -1;
        int fixedJ = -1;
        for (int i = 0; i < grid.length; i++) {
            for (int j = 0; j < grid[0].length; j++) {
                if (grid[i][j] == 0) {
                    // 相邻岛屿面积(去重)
                    int fixedArea = fixedArea(grid, i, j, areas);
                    if (fixedArea > maxArea) {
                        maxArea = fixedArea;
                        fixedI = i;
                        fixedJ = j;
                    }
                }
            }
        }
        // 没有海洋
        if (fixedI == -1 && fixedJ == -1) {
            maxArea = grid.length * grid[0].length;
        }
        return maxArea;
    }

    private static int areaFlag(int[][] grid, int r, int c, int flag) {
        if (!inGrid(grid, r, c)) {
            return 0;
        }

        // 防止重复遍历
        if (1 != grid[r][c]) {
            return 0;
        }

        // 标记已遍历过
        grid[r][c] = flag;

        return 1 + areaFlag(grid, r, c - 1, flag) + areaFlag(grid, r, c + 1, flag)
                + areaFlag(grid, r - 1, c, flag) + areaFlag(grid, r + 1, c, flag);
    }

    private static int fixedArea(int[][] grid, int r, int c, Vector<Integer> areas) {
        final int INIT_FLAG = 2;
        int maxRow = grid.length;
        int maxCol = grid[0].length;
        int largestArea = 1;
        Set<Integer> flagSet = new HashSet<>();
        if (grid[r - 1][c] > 0 && r > 0 && !flagSet.contains(grid[r - 1][c])) {
            largestArea += areas.get(grid[r - 1][c] - INIT_FLAG);
            flagSet.add(grid[r - 1][c]);
        }
        if (grid[r + 1][c] > 0 && (r < maxRow - 1) && !flagSet
                .contains(grid[r + 1][c])) {
            largestArea += areas.get(grid[r + 1][c] - INIT_FLAG);
            flagSet.add(grid[r + 1][c]);
        }
        if (grid[r][c - 1] > 0 && c > 0 && !flagSet.contains(grid[r][c - 1])) {
            largestArea += areas.get(grid[r][c - 1] - INIT_FLAG);
            flagSet.add(grid[r][c - 1]);
        }
        if (grid[r][c + 1] > 0 && (c < maxCol - 1) && !flagSet
                .contains(grid[r][c + 1])) {
            largestArea += areas.get(grid[r][c + 1] - INIT_FLAG);
            flagSet.add(grid[r][c + 1]);
        }
        return largestArea;
    }

    public static void main(String[] args) {
        /*int[][] grid = {
                {0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
                {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0},
                {0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
                {0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0},
                {0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0},
                {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
                {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0},
                {0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0}
        };*/
        /*int[][] grid = {
                {1, 0},
                {0, 1}
        };*/
        int[][] grid = {
                {0, 1, 0, 1, 1},
                {1, 1, 1, 0, 0},
                {1, 1, 0, 0, 1},
                {0, 1, 0, 0, 1}
        };
        LOG.info("" + largestIsland(grid));
    }
}
```


!!! quote "参考链接"
    - [LeetCode 例题精讲 | 12 岛屿问题：网格结构中的 DFS](https://mp.weixin.qq.com/s?__biz=MzA5ODk3ODA4OQ==&mid=2648167208&idx=1&sn=d8118c7c0e0f57ea2bdd8aa4d6ac7ab7&chksm=88aa236ebfddaa78a6183cf6dcf88f82c5ff5efb7f5c55d6844d9104b307862869eb9032bd1f&token=1064083695&lang=zh_CN&scene=21#wechat_redirect)
