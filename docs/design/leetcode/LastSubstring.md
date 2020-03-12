# LastSubstring

```java
import java.util.Arrays;

/**
 * 1163. 按字典序排在最后的子串
 * @since 2020-03-11
 *
 * 给你一个字符串 s，找出它的所有子串并按字典序排列，返回排在最后的那个子串。
 *
 * 示例 1：
 * 输入："abab"
 * 输出："bab"
 * 解释：我们可以找出 7 个子串 ["a", "ab", "aba", "abab", "b", "ba", "bab"]。按字典序排在最后的子串是 "bab"。
 *
 * 示例 2：
 * 输入："leetcode"
 * 输出："tcode"
 *
 * 提示：
 * 1 <= s.length <= 4 * 10^5
 * s 仅含有小写英文字符。
 *
 * 来源：力扣（LeetCode）
 * 链接：https://leetcode-cn.com/problems/last-substring-in-lexicographical-order
 * 著作权归领扣网络所有。商业转载请联系官方授权，非商业转载请注明出处。
 */
public class LastSubstring {
    public String lastSubstring(String s) {
        int len = s.length();
        char[] inputChars = s.toCharArray();
        int currentMaxIndex = 0;
        for (int compareIndex = 1; compareIndex < len; compareIndex++) {
            boolean needContinue = false;
            for (int i = 0; i < len - compareIndex; i++) {
                if (inputChars[compareIndex + i] < inputChars[currentMaxIndex + i]) {
                    needContinue = true;
                    break;
                } else if (inputChars[compareIndex + i] > inputChars[currentMaxIndex + i]) {
                    currentMaxIndex = compareIndex;
                    needContinue = true;
                    break;
                }
            }
            if (!needContinue) {
                break;
            }
        }
        return s.substring(currentMaxIndex);
    }

    public static void main(String args[]) {
        LastSubstring lsb = new LastSubstring();
        System.out.println(lsb.lastSubstring("abab"));
        System.out.println(lsb.lastSubstring("leetcode"));
        System.out.println(lsb.lastSubstring("zrziy"));  // zrziy
        System.out.println(lsb.lastSubstring("cacacb"));  // cb
        // 200000个a
        char[] longestChars = new char[200000];
        Arrays.fill(longestChars, 'a');
        long startTime = System.currentTimeMillis();
        System.out.println(lsb.lastSubstring(String.valueOf(longestChars)));
        System.out.println(System.currentTimeMillis() - startTime);
    }
}
```
