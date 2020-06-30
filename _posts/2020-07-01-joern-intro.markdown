---
layout: post
title: "Code analysis with Joern"
date: 2020-07-01 00:18:00 +0530
categories: blog
---

# Introduction

Joern is a tool for vulnerability analysis. It is based on code-property
graphs. The official documentation has a lot more information about it
[here](https://joern.io/).

Joern supports a Scala based extensible query language which I found to be
really cool and fun to use.

In this post, I'm going to cover some basic queries which I find to be useful.
In my next post, I will go through a real world example on the U-Boot source
code.

One of the great things about Joern is, that you don't have to build the
project you are targeting for you to query it (whereas when you use something
like CodeQL, it is a pre-requisite). This is really a plus point, especially
for projects which are difficult to build or when only partial source code is
available.

I will go over some basic examples here.

# Data flow examples

## Case 1

Suppose we have the following snippet of code:

{% highlight c %}
// we want to find this
void f(char* buf, int x) {
    int n = ntohl(x);
    char* s = malloc(10);
    memcpy(s, buf, n);
}

// we don't want to find this
void g(char*buf, int x) {
    int a = ntohl(x);
    int b = 5;
    char* s = malloc(10);
    memcpy(s, buf, b);
}
{% endhighlight %}

Our goal is to look for calls to `memcpy` where the size argument may be
controlled by user data. A common function which is used in networking projects
to receive user-input is `ntohl` from the `ntohs`, `ntohl`, `ntohll` family of
functions.

`ntoh` is used for converting data from network byte order to host byte order.

In the example above, we're interested in the flow in function `g` where the
size parameter of `memcpy` is directly influenced by the data returned from the
call to `ntohl`.

To do this, we can write the following query.

{% highlight scala %}
def getFlow() = {
    val src = cpg.call.name("ntohl")
    val sink = cpg.call.name("memcpy").argument.order(3)
    sink.reachableByFlows(src).p
}
{% endhighlight %}

Here we are defining our source as the return value from the `ntohl` function
call.
Our sink is the third argument of the call to `memcpy`.

Then we use Joern's `reachableByFlows` API to find a data-flow path from source
to sink.

`NOTE`: Joern does not support inter-procedural data-flow analysis in it's
current release. That means it will not track data-flow across function
boundaries. Anyway, we'll see how to write our queries to do this manually

Anyway, here is the result we get from running our query:

```
joern> getFlow 
res2: List[String] = List(
  """____________________________________________________________________________________
| tracked          | lineNumber| method| file                                       |
|===================================================================================|
| ntohl(x)         | 6         | f     | /Users/jai/wd/tmp/vuln/tests/flow/one/one.c|
| n = ntohl(x)     | 6         | f     | /Users/jai/wd/tmp/vuln/tests/flow/one/one.c|
| memcpy(s, buf, n)| 8         | f     | /Users/jai/wd/tmp/vuln/tests/flow/one/one.c|
"""
)
```

Okay, now let's look at another example.

## Case 2

{% highlight c %}
int f (int n) {
    int x = ntohl(n);
    return x;
}

int g (int n) {
    int x = ntohl(n);
    return 42;
}

void foo (int a, char* buf) {
    int n = f(a);
    char* s = malloc(100);
    memcpy(s, buf, n);
}

void bar (int a, char* buf) {
    int n = g(a);
    char* s = malloc(100);
    memcpy(s, buf, n);
}
{% endhighlight %}

Here we have two functions, `f` and `g`.

`f` reads a value using `ntohl` and returns it.
`g` reads a value using `ntohl` but always returns 42.

For this example, we are still looking for flows from calls to `ntohl` to the
size argument of `memcpy`. But since Joern doesn't support inter-procedural
taint analysis, we will have to write a query which will find such cases.

To do this, we can write a query like so:

{% highlight scala %}
def getFlow() = {
    // this gives us methods which call ntohl
    val methods = cpg.method.name("ntohl").caller

    // we want to filter those methods where the value returned by
    // ntohl is returned by the method
    val filteredMethods = methods.l.filter(
        method => {
            val src = method.start.ast.isCallTo("ntohl")
            val sink = method.start.methodReturn
            sink.reachableBy(src)
        }.size > 0
    ).start

    // we will treat call to these filtered methods as good as a call to
    // ntohl. this is will only get one layer of calls though...
    val srcs = filteredMethods.name.l.map(cpg.call.name(_))
    val sink = cpg.call.name("memcpy").argument.order(3)

    srcs.map(sink.reachableByFlows(_).p)
}
{% endhighlight %}

We look for functions which call `ntohl`, and then we treat such functions as
our source. Our sink still remains the same. We then add another constraint.
For functions which call `ntohl`, we check to see if the value returned by the
function is influenced by the value returned from `ntohl`.

And indeed, this gives us the flow we are look for.

```
joern> getFlow 
res2: List[List[String]] = List(
  List(
    """____________________________________________________________________________________
| tracked          | lineNumber| method| file                                       |
|===================================================================================|
| f(a)             | 15        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/two/two.c|
| n = f(a)         | 15        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/two/two.c|
| memcpy(s, buf, n)| 17        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/two/two.c|
"""
  )
)
```

This query is not foolproof though. It won't find such patterns if the function
call to ntohl is 2 layers deep. It also only accounts for functions where the
value read using `ntohl` is returned by the function. This will not be able to
find functions where the value returned from `ntohl` is used to update a
pointer passed as an argument to the function.

## Case 3

This is the source code which we will use for our third example:

{% highlight c %}
// we want to find this
void g (char* buf, int n) {
    char* s = malloc(10);
    memcpy(s, buf, n);
}

void foo (int n) {
    int x = ntohl(n);
    char* s = malloc(x);
    g(s, x);
}

// we don't want this one since it does not use `n`
// in the call to `memcpy`
// we're still getting this in the current version of Joern though
// it looks like Joern does not support argument level granularity
void h (char* buf, int n) {
    char* s = malloc(10);
    int x = 10;
    memcpy(s, buf, x);
}

void bar (int n) {
    int x = ntohl(n);
    char* s = malloc(x);
    h(s, x);
}

// we definitely shouldn't be getting this since any of the arguments
// in the memcpy call are reachable from the method parameters
void i (char* buf, int n) {
    char* t = malloc(10);
    char* s = malloc(10);
    int x = 10;
    memcpy(s, t, x);
}

void baz (int n) {
    int x = ntohl(n);
    char* s = malloc(x);
    i(s, x);
}
{% endhighlight %}

In this example, we have the call to `memcpy` in another function, instead of
the call to `ntohl`. FOr example, in the function `foo`, `h` is called which in
turn calls `memcpy` with a value which is tainted by `ntohl`.

We also have some counter-examples which we don't want to find. In the `bar`
function, we are calling `h` which does not use a tainted size parameter in the
call to `memcpy`. Similarly for `baz` and `i`.

We can write our query as follows:

{% highlight scala %}
def getFlow() = {
    val methods = cpg.method.name("memcpy").caller
    val filteredMethods = methods.l.filter(
        method => {
            val src = method.start.parameter
            val sink = method.start.ast.isCallTo("memcpy").argument.order(3)
            sink.reachableBy(src)
        }.size > 0
    ).start

    val src = cpg.call.name("ntohl")
    val sink = filteredMethods.parameter.argument
    sink.reachableByFlows(src).p
}
{% endhighlight %}

Here we search for functions which call `memcpy`. Then for those functions, we
check to see if any of the function arguments can influence the size parameter
of `memcpy` (we are assuming that data tainted by `ntohl` will be passed as an
argument to a function).
If this is the case, we treat the parameters of these filtered functions as the
sink and the return values of `ntohl` as the source.

This gives us the following results:

```
joern> getFlow 
res2: List[String] = List(
  """___________________________________________________________________________________
| tracked     | lineNumber| method| file                                           |
|==================================================================================|
| ntohl(n)    | 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)| 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| h(s, x)     | 29        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """___________________________________________________________________________________
| tracked     | lineNumber| method| file                                           |
|==================================================================================|
| ntohl(n)    | 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)| 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| h(s, x)     | 29        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """______________________________________________________________________________________
| tracked        | lineNumber| method| file                                           |
|=====================================================================================|
| ntohl(n)       | 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)   | 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| malloc(x)      | 28        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| * s = malloc(x)| 28        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| h(s, x)        | 29        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """______________________________________________________________________________________
| tracked        | lineNumber| method| file                                           |
|=====================================================================================|
| ntohl(n)       | 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)   | 27        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| malloc(x)      | 28        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| * s = malloc(x)| 28        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| h(s, x)        | 29        | bar   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """___________________________________________________________________________________
| tracked     | lineNumber| method| file                                           |
|==================================================================================|
| ntohl(n)    | 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)| 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| g(s, x)     | 13        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """___________________________________________________________________________________
| tracked     | lineNumber| method| file                                           |
|==================================================================================|
| ntohl(n)    | 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)| 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| g(s, x)     | 13        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """______________________________________________________________________________________
| tracked        | lineNumber| method| file                                           |
|=====================================================================================|
| ntohl(n)       | 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)   | 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| malloc(x)      | 12        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| * s = malloc(x)| 12        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| g(s, x)        | 13        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
""",
  """______________________________________________________________________________________
| tracked        | lineNumber| method| file                                           |
|=====================================================================================|
| ntohl(n)       | 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| x = ntohl(n)   | 11        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| malloc(x)      | 12        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| * s = malloc(x)| 12        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
| g(s, x)        | 13        | foo   | /Users/jai/wd/tmp/vuln/tests/flow/three/three.c|
"""
)
```

This gives us quite a number of results. The reason is that it prints all
possible paths from source to sink.

There is a problem here though. We are getting results for `bar` (which calls
`h`) as well. The reason we are getting these paths is, it seems Joern does
not support argument level granularity in taint tracking yet. Since in the
function `h`, the parameter `buf` reaches the call to `memcpy`, it is
satisfying the condition:

{% highlight scala %}
val src = method.start.parameter
val sink = method.start.ast.isCallTo("memcpy").argument.order(3)
sink.reachableBy(src)
{% endhighlight %}

No harm done, we can manually filter out such results.

## Case 4

This is the final example we'll look at today.

{% highlight c %}
int f (int x) {
    int n = ntohl(x);
    return n;
}

int g (int x) {
    int n = f(x);
    return n;
}

int h (int x) {
    int n = g(x);
    return n;
}

void foo(char* buf, int n) {
    int sz = h(n);
    char* s = malloc(10);
    memcpy(s, buf, sz);
}
{% endhighlight %}

In this example, we have several layers of function calls through which we
need to track data-flow.


