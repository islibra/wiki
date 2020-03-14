# DelOneSort

```java
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * OJ考题代码：剔一排序
 * 给定数组, 是否能剔除一个元素后有序, 返回剔除元素, 否则返回-1
 *
 * 2  数组长度
 * 2 1  数组
 * -1  返回
 *
 * 5
 * 1 3 2 4 4
 * 2
 *
 * 5
 * 1 2 3 4 5
 * -1
 *
 * @author 命题组
 * @since 2020-1-22
 */
public class DelOneSort {
    /**
     * main入口由OJ平台调用
     */
    public static void main(String[] args) {
        Scanner cin = new Scanner(System.in, StandardCharsets.UTF_8.name());
        int length = cin.nextInt();
        int[] nums = new int[length];
        for (int i = 0; i < length; i++) {
            nums[i] = cin.nextInt();
        }
        cin.close();

        System.out.println(delOneSort(nums));
    }

    static int delOneSort(int[] nums) {
        if (nums.length < 3) {
            return -1;
        }
        // 是否升序
        boolean isAsc = true;

        // 是否降序
        boolean isDesc = true;

        // 升序忽略索引
        int ascIgnore = -1;

        // 降序忽略索引
        int descIgnore = -1;

        for (int i = 1; i < nums.length; i++) {
            if (nums[i] > nums[i - 1]) {
                if (descIgnore == -1) {
                    descIgnore = i;
                } else {
                    isDesc = false;
                }
            } else if (nums[i] < nums[i - 1]) {
                if (ascIgnore == -1) {
                    ascIgnore = i;
                } else {
                    isAsc = false;
                }
            }
        }

        int result = -1;
        if (isAsc && ascIgnore != -1) {
            result = nums[ascIgnore];
        }
        if (isDesc && descIgnore != -1) {
            if ((result != -1 && nums[descIgnore] < nums[ascIgnore]) || result == -1) {
                result = nums[descIgnore];
            }
        }

        return result;
    }
}
```
