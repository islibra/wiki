# Collection

- java.util.Collection<E>
    - AbstractCollection
    - List
        - AbstractList
            - ArrayList: 数组
            - Vector: 动态数组, **线程同步**
                - Stack

            - LinkedList: 链表

    - Set: **去重**
        - AbstractSet
            - HashSet: 以hashcode和equals方法来判断是否同一个元素
                - LinkedHashSet

            - TreeSet: 以二叉树对插入元素进行 **排序**, 元素需实现Comparable接口并重写compareTo()

        - SortedSet

    - Queue

- Map
    - AbstractMap
        - HashMap: 根据键的hashCode存储数据, 应使用 **ConcurrentHashMap** 保证线程安全, 引入了分段锁, 并发 **优于Hashtable**
            - LinkedHashMap

        - Hashtable: 遗留类, 继承自Dictionary, **线程安全**
        - TreeMap: 根据键 **排序**
        - IdentityHashMap
        - WeakHashMap

    - SortedMap

- Iterator
    - LinkIterator

- Comparable
- Comparator
- Collections
- Arrays


!!! quote "参考链接: [Java集合List、Set、Map](https://mp.weixin.qq.com/s/he5d-RsifuqIN3dYc6yc9A)"
