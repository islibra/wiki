# GetPathOfCapacity

```java
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.Stack;

/**
 * OJ考题代码：树形网络
 * 考点: 深度优先搜索 + 快速排序
 * 给一个树和每个节点的容量, 判断从根到叶子哪条路径的总容量等于目标容量
 *
 * 输入:
 * 20 9 24  总节点数 非叶子节点数 目标容量
 * 10 2 4 3 5 10 2 18 9 7 2 2 1 3 12 1 8 6 2 2  按照节点ID每个节点的容量
 * 00 4 01 02 03 04  非叶子节点ID 子节点数 子节点ID
 * 02 1 05
 * 04 2 06 07
 * 03 3 11 12 13
 * 06 1 09
 * 07 2 08 10
 * 16 1 15
 * 13 3 14 16 17
 * 17 2 18 19
 *
 * 输出:  按非升序将每条路径分别输出
 * 10 5 2 7  符合条件的路径上的容量
 * 10 4 10
 * 10 3 3 6 2
 * 10 3 3 6 2
 *
 * @author 命题组
 * @since 2020-1-22
 */
public class GetPathOfCapacity {
    /**
     * main入口由OJ平台调用
     */
    public static void main(String[] args) {
        Scanner cin = new Scanner(System.in, StandardCharsets.UTF_8.name());

        int nodeNum = cin.nextInt();
        int nonLeafNodeNum = cin.nextInt();
        int targetCapacity = cin.nextInt();

        int[] capacitys = new int[nodeNum];
        for (int i = 0; i < nodeNum; i++) {
            capacitys[i] = cin.nextInt();
        }

        NonLeafNode[] nonLeafNodes = new NonLeafNode[nonLeafNodeNum];
        for (int i = 0; i < nonLeafNodeNum; i++) {
            int nodeId = cin.nextInt();
            int subNodeNum = cin.nextInt();
            nonLeafNodes[i] = new NonLeafNode(nodeId, subNodeNum);
            for (int j = 0; j < subNodeNum; j++) {
                nonLeafNodes[i].subNodeIds[j] = cin.nextInt();
            }
        }
        cin.close();

        String[] paths = getPathOfCapacity(capacitys, nonLeafNodes, targetCapacity);
        if (paths != null) {
            for (String path : paths) {
                System.out.println(path);
            }
        }
    }

    static class NonLeafNode {
        int nodeId;
        int[] subNodeIds;

        NonLeafNode(int nodeId, int subNodeNum) {
            this.nodeId = nodeId;
            this.subNodeIds = new int[subNodeNum];
        }
    }

    static NonLeafNode getNodeByID(NonLeafNode[] nonLeafNodes, int nodeID) {
        for (NonLeafNode node : nonLeafNodes) {
            if (nodeID == node.nodeId) {
                return node;
            }
        }
        return null;
    }

    static int[] append(int[] s, int pivot, int[] b) {
        int len = s.length + b.length + 1;
        int[] result = new int[len];
        System.arraycopy(s, 0, result, 0, s.length);
        result[s.length] = pivot;
        System.arraycopy(b, 0, result, s.length + 1, b.length);
        return result;
    }

    /**
     * 快速排序
     *
     * @param ary 输入的nodeID数组
     * @return 排序后的nodeID数组
     */
    static int[] quickSort(int[] capacitys, int[] ary) {
        int len = ary.length;
        if (len < 2) {
            return ary;
        } else {
            // 基准值
            int pivotID = ary[0];
            int pivot = capacitys[ary[0]];
            // 比基准值小
            int[] smallIDs = new int[len];
            int slen = 0;
            // 比基准值大
            int[] bigIDs = new int[len];
            int blen = 0;
            for (int i = 1; i < ary.length; i++) {
                if (capacitys[ary[i]] <= pivot) {
                    smallIDs[slen] = ary[i];
                    slen++;
                } else if (capacitys[ary[i]] > pivot) {
                    bigIDs[blen] = ary[i];
                    blen++;
                }
            }
            return append(quickSort(capacitys, Arrays.copyOf(smallIDs, slen)), pivotID,
                    quickSort(capacitys, Arrays.copyOf(bigIDs, blen)));
        }
    }

    static String[] getPathOfCapacity(int[] capacitys, NonLeafNode[] nonLeafNodes, int targetCapacity) {
        Stack<Integer> stack = new Stack<>();
        // 加入根节点
        stack.push(0);
        int sum = 0;

        // 已将子节点加入
        Set joinedNode = new HashSet();

        List<Integer> resultList = new ArrayList();
        while (!stack.isEmpty()) {
            // 取栈顶元素
            int top = stack.peek();
            if (!joinedNode.contains(top)) {
                sum += capacitys[top];
                if (sum > targetCapacity) {
                    sum -= capacitys[top];
                    stack.pop();
                    continue;
                }
                resultList.add(top);

                NonLeafNode topNode = getNodeByID(nonLeafNodes, top);
                // 叶子节点
                if (topNode == null) {
                    if (sum == targetCapacity) {
                        // 找到一条路径
                        System.out.println(resultList);
                    }
                    sum -= capacitys[top];
                    resultList.remove(Integer.valueOf(top));
                    stack.pop();
                    continue;
                }
                // 将子节点按容量从小到大的顺序入栈
                int[] nodes = quickSort(capacitys, topNode.subNodeIds);
                for (int node : nodes) {
                    stack.push(node);
                }
                joinedNode.add(top);
            } else {
                sum -= capacitys[top];
                resultList.remove(Integer.valueOf(top));
                stack.pop();
            }
        }

        List<String> result = new ArrayList();
        return null;
    }
}
```
