---
layout: post
title: 经典编程题目
categories: Java
tags: [Java]
---

#### 1.栈实现队列
用两个栈实现一个队列，完成入队出队
思想：stack1作为入队的栈，出队的时候从stack2出来，stack2是stack1倒叙得到的，所以出队出最上面的元素就是队列最前面的元素。

{% highlight java linenos %}
import java.util.Stack;

public class Solution {
    Stack<Integer> stack1 = new Stack<Integer>();
    Stack<Integer> stack2 = new Stack<Integer>();
    
    public void push(int node) {
        stack1.push(node);
    }
    
    public int pop() {
        //为空的话，再看stack1，1出栈放到2中，2最上面的元素在出栈
        if (stack2.size() <= 0) {
                while (stack1.size() != 0) {
                    stack2.push(stack1.pop());
                }
            }
        return stack2.pop();
    }
}
{% endhighlight %}

#### 2.二分查找
查找数组中第一个查找值，返回其位置（从1开始），找不到就返回数组长度+1

{% highlight java linenos %}
import java.util.*;

public class Solution {
    /**
     * 二分查找
     * @param n int整型 数组长度
     * @param v int整型 查找值
     * @param a int整型一维数组 有序数组
     */
    public int upper_bound_ (int n, int v, int[] a) {
        // write code here
        int left = 0,right = n-1;
        int mid = 0;
        if(a[0] > v){
            return 1;
        }
        while(left <= right){
            mid =(right + left)/2;
            if(a[mid] > v){
                right = mid -1;
            }else if(a[mid] < v){

                left = mid + 1;
            }else{
                while(mid >=0 && a[mid] == v){
                    mid--;
                }
                return mid + 2;
            }
        }
        return n + 1;
    }
}
{% endhighlight %}

#### 3.计算二叉树的深度

{% highlight java linenos %}
int treeDepth(TreeNode root) {
    if(root != null) {
        int left = treeDepth(root.left);//计算左子树的深度
        int right = treeDepth(root.right);//计算右子树的深度
        return left > right ? left + 1 : right + 1;
    }
    return 0;
}
{% endhighlight %}
