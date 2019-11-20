# stack_queue

## 栈

!!! abstract "LIFO: 后进先出"

### 基本操作

- 初始化
- 压入栈
- 弹出栈顶元素
- 查看栈顶元素
- 判空

!!! example "典型应用: 函数调用栈 --> 栈溢出"

```java
package structure;

import java.util.EmptyStackException;
import java.util.Stack;

/**
 * 20. 有效的括号
 * <p>
 * 给定一个只包括 '('，')'，'{'，'}'，'['，']' 的字符串，判断字符串是否有效。
 * 有效字符串需满足：
 * 左括号必须用相同类型的右括号闭合。
 * 左括号必须以正确的顺序闭合。
 * 注意空字符串可被认为是有效字符串。
 * <p>
 * 示例 1:
 * 输入: "()"
 * 输出: true
 * <p>
 * 示例 2:
 * 输入: "()[]{}"
 * 输出: true
 * <p>
 * 示例 3:
 * 输入: "(]"
 * 输出: false
 * <p>
 * 示例 4:
 * 输入: "([)]"
 * 输出: false
 * <p>
 * 示例 5:
 * 输入: "{[]}"
 * 输出: true
 * <p>
 * 示例 6:
 * 输入: "]"
 * 输出: false
 * <p>
 * 链接：https://leetcode-cn.com/problems/valid-parentheses
 */
public class ValidBrackets {

    public boolean isValid(String s) {
        Stack stack = new Stack();
        try {
            char[] cArray = s.toCharArray();
            for (char c : cArray) {
                if (c == '(' || c == '[' || c == '{') {
                    stack.push(c);
                } else if (c == ')') {
                    char top = (char) stack.pop();
                    if (top != '(') {
                        return false;
                    }
                } else if (c == ']') {
                    char top = (char) stack.pop();
                    if (top != '[') {
                        return false;
                    }
                } else if (c == '}') {
                    char top = (char) stack.pop();
                    if (top != '{') {
                        return false;
                    }
                } else {
                    continue;
                }
            }
        } catch (EmptyStackException e) {
            return false;
        }
        return stack.empty();
    }

    public static void main(String args[]) {
        ValidBrackets vb = new ValidBrackets();
        String s1 = "()";
        System.out.println(vb.isValid(s1));
        String s2 = "()[]{}";
        System.out.println(vb.isValid(s2));
        String s3 = "(]";
        System.out.println(vb.isValid(s3));
        String s4 = "([)]";
        System.out.println(vb.isValid(s4));
        String s5 = "{[]}";
        System.out.println(vb.isValid(s5));
        String s6 = "]";
        System.out.println(vb.isValid(s6));
    }
}
```
