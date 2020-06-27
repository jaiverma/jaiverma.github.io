---
layout: post
title: "Joern U-Boot"
date: 2020-06-21 17:30:00 +0530
categories: blog
---
I've been playing around with a tool called
[joern](https://github.com/ShiftLeftSecurity/joern) for some time now. Joern is
a static analysis tool which is maintained by ShiftLeft. Joern uses something
called code property graphs for representing different source code.

The tool is written in Scala and has support for a powerful query language.
Technical details are present on the official website
[here](https://joern.io/docs/). Implementation details are present in
[this](https://www.sec.cs.tu-bs.de/pubs/2014-ieeesp.pdf) research paper.

I feel that this tool is similar to
[CodeQL](https://securitylab.github.com/tools/codeql). Some reasons I like
Joern over CodeQL are:

- The query language for Joern is very easy to use and learn, whereas I found
CodeQL to be much more difficult. I found Joern's query language to be much
simpler that CodeQL.

- You don't have to build a project for use with Joern. Joern is bundled with a
fuzzy source code parser which is able to generate a code property graph
without actually building the code. This is both good and bad. The good part is
that you can use Joern even when you don't have the full source code so you
don't have to spend time in getting a working build (this is especially
beneficial for embedded code bases). The bad part is that the accuracy of the
queries decreases as compared to CodeQL.

- One major disadvantage of Joern is, that it currently does not support
inter-procedural taint-analysis (which is possible with CodeQL).

I will go over some example use-cases of Joern using some test programs.

#### Basic API

Considering the following source code:

{% highlight c %}
int add_one(int x) {
    return x + 1;
}

int main() {
    char* buf = malloc(4);
    int x = 2;
    double y = 3.5;

    x = add_one(x);
    printf("x is %d\n", x);
}
{% endhighlight %}

We can generate the `cpg` for this program as follows:

{% highlight shell_session %}
[example] joern-parse .
{% endhighlight %}

We can then open up the `joern repl` and run some queries:

{% highlight shell_session %}
[example] joern
Compiling (synthetic)/ammonite/predef/interpBridge.sc
Compiling (synthetic)/ammonite/predef/replBridge.sc
Compiling (synthetic)/ammonite/predef/sourceBridge.sc
Compiling (synthetic)/ammonite/predef/frontEndBridge.sc
Compiling (synthetic)/ammonite/predef/DefaultPredef.sc
Compiling /Users/jai/wd/tmp/vuln/example/(console)
creating workspace directory: /Users/jai/wd/tmp/vuln/example/workspace

     ██╗ ██████╗ ███████╗██████╗ ███╗   ██╗
     ██║██╔═══██╗██╔════╝██╔══██╗████╗  ██║
     ██║██║   ██║█████╗  ██████╔╝██╔██╗ ██║
██   ██║██║   ██║██╔══╝  ██╔══██╗██║╚██╗██║
╚█████╔╝╚██████╔╝███████╗██║  ██║██║ ╚████║
 ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
      
Type `help` or `browse(help)` to begin
joern>
{% endhighlight %}

Before we can run any queries, we have to load the generated `cpg`.

{% highlight scala %}
joern> importCpg("cpg.bin")
Creating project `cpg.bin` for CPG at `cpg.bin`
Creating working copy of CPG to be safe
Loading base CPG from: /Users/jai/wd/tmp/vuln/example/workspace/cpg.bin/cpg.bin.tmp
{% endhighlight %}

We can print our `identifiers` present in the program:

{% highlight scala %}
joern> cpg.identifier.name.p
res1: List[String] = List("y", "x", "x", "x", "buf", "x", "x")
{% endhighlight %}

We can print the functions present in the program:

{% highlight scala %}
joern> cpg.method.name.p
res2: List[String] = List(
  "printf",
  "<operator>.assignment",
  "<operator>.addition",
  "add_one",
  "malloc",
  "main"
)
{% endhighlight %}

We can print the location of calls in the program. `joern` considers assignment
to be a call as well (a call to the `Operators.assignment` function). We can
list these with:

{% highlight scala %}
def getCalls(function: String) = {
    cpg.call.name(function)
        .l
        .map(
            call => (
                call.method.name,
                call.code,
                call.location.filename,
                call.location.lineNumber match {
                    case Some(n) => n.toString
                    case None => "n/a"
                }
            )
        )
}
{% endhighlight %}

We can then call this function with any function name:

{% highlight scala %}
joern> getCalls("<operator>.assignment")
res6: List[(String, String, String, String)] = List(
  ("main", "x = add_one(x)", "/Users/jai/wd/tmp/vuln/example/main.c", "13"),
  ("main", "y = 3.5", "/Users/jai/wd/tmp/vuln/example/main.c", "11"),
  ("main", "x = 2", "/Users/jai/wd/tmp/vuln/example/main.c", "10"),
  ("main", "* buf = malloc(4)", "/Users/jai/wd/tmp/vuln/example/main.c", "9")
)
{% endhighlight %}

We can also get flow from one operation to another. For example, if we want to
see the trasformations on variable `x` from it's definition to the call to
`printf`, we can do the following:

{% highlight scala %}
joern> val src = cpg.identifier.name("x")
src: NodeSteps[Identifier] = io.shiftleft.semanticcpg.language.NodeSteps@54d30bfd

joern> val sink = cpg.call.name("printf").argument 
sink: NodeSteps[Expression] = io.shiftleft.semanticcpg.language.NodeSteps@1eee1b2b

joern> sink.reachableByFlows(src).p
res10: List[String] = List(
  """___________________________________________________________________________________
| tracked               | lineNumber| method| file                                 |
|==================================================================================|
| x = 2                 | 10        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
| add_one(x)            | 13        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
| x = add_one(x)        | 13        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
| printf("x is %d\n", x)| 14        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
""",
...
{% endhighlight %}

We can make this a little more generic. If we want to track flow from variables
to calls to printf for any given method, we can do:

{% highlight scala %}
def getFlow(method: String) = {
    val src = cpg.method.name(method)
        .local
        .referencingIdentifiers

    val sink = cpg.call.name("printf")
        .argument

    sink.reachableByFlows(src).p
}
{% endhighlight %}

Running this for `main` gives us the same output:

{% highlight scala %}
joern> getFlow("main") 
res20: List[String] = List(
  """___________________________________________________________________________________
| tracked               | lineNumber| method| file                                 |
|==================================================================================|
| x = 2                 | 10        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
| add_one(x)            | 13        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
| x = add_one(x)        | 13        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
| printf("x is %d\n", x)| 14        | main  | /Users/jai/wd/tmp/vuln/example/main.c|
""",
...
{% endhighlight %}

Now for some examples where we try to find some bugs:

#### Heap based buffer-overflow

We will consider the following snippet of code for this example:

{% highlight c %}
int get_tainted_int(int fd) {
    int x;
    read(fd, &x, sizeof(int));
    return x;
}

void copy(char *s, int n) {
    char* buf = malloc(100);
    memcpy(buf, s, n);
}

int main() {
    int fd = open("/tmp/x", O_RDONLY);
    int sz = get_tainted_int(fd);
    char* str = malloc(sz);

    copy(str, sz);

    close(fd);
    return 0;
}
{% endhighlight %}

The program is vulnerable to a heap-based buffer overflow in the function
`copy`. The parameter `n` is not validated to be less than the size of the
buffer before the call to memcpy.

To discover this bug, we want to search for the following pattern:

- Calls to `memcpy` where the size argument is tainted (can be controlled by
user input)

- Calls to `memcpy` where destination buffer size is not equal to the size
parameter passed to `memcpy`.

To figure out which functions can taint variables, we have to do some manual
code review. For instance, in our example, the function `get_tainted_int` is
using the `read` function to read data from an untrusted file.

To decrease the effort in manual code review, we can first use Joern to filter
which functions could be returning tainted data. Some of the functions which
could taint variables include `read`, `ntohl`, `recv`, ...

We can get these functions with:

{% highlight scala %}
cpg.method.name("(read|ntohs|ntohl|recv)").caller.l.map(method => method.name)
res7: List[String] = List("get_tainted_int")
{% endhighlight %}

To do some more automated analysis, we could see if flow from the call to
`read` to the return value of the function. This won't be applicable for
functions which don't return a value, and instead update the value passed as a
pointer argument to the function.

Also, I had some difficulties with Joern here, and there seem to be some
inconsistencies. In the call to `read`, we are passing `&x` as second argument.

Here `&x` is treated as a call to `Operators.addressOf` by Joern.

{% highlight scala %}
joern> cpg.call.name("read").argument.order(2).l
res7: List[Expression] = List(
  Call(
    id -> 13L,
    code -> "&x",
    name -> "<operator>.addressOf",
    order -> 2,
    methodInstFullName -> None,
    methodFullName -> "<operator>.addressOf",
    argumentIndex -> 2,
    dispatchType -> "STATIC_DISPATCH",
    signature -> "TODO assignment signature",
    typeFullName -> "ANY",
    dynamicTypeHintFullName -> List(),
    lineNumber -> Some(10),
    columnNumber -> Some(13),
    resolved -> None,
    depthFirstOrder -> None,
    internalFlags -> None
  )
)
{% endhighlight %}

The problem I faced was that joern was not able to discover a path between the
identifier `x`, and the call to `read`.

{% highlight scala %}
joern> val src = cpg.identifier.name("x")
src: NodeSteps[Identifier] = io.shiftleft.semanticcpg.language.NodeSteps@7da1010a

joern> val sink = cpg.call.name("read").argument.order(2)
sink2: NodeSteps[Expression] = io.shiftleft.semanticcpg.language.NodeSteps@75a000d8

joern> sink2.reachableByFlows(src).p
res10: List[String] = List()
{% endhighlight %}

I have encountered lots of places where Joern gives inconsistent results.

Anyway, we are still able to find a path from the local variables of the
function to the return value.

{% highlight scala %}
joern> val src = cpg.method.name("get_tainted_int").local.referencingIdentifiers
src: NodeSteps[Identifier] = io.shiftleft.semanticcpg.language.NodeSteps@46b38c69

joern> val sink = cpg.method.name("get_tainted_int").methodReturn
sink: NodeSteps[MethodReturn] = io.shiftleft.semanticcpg.language.NodeSteps@10c405d

joern> sink.reachableByFlows(src).p
res13: List[String] = List(
  """________________________________________________________________________________
| tracked  | lineNumber| method         | file                                  |
|===============================================================================|
| return x;| 11        | get_tainted_int| /Users/jai/wd/tmp/vuln/overflow/main.c|
| RET      | 8         | get_tainted_int| /Users/jai/wd/tmp/vuln/overflow/main.c|
"""
)
{% endhighlight %}

So I would recommend a hybrid approach here. You can use Joern to filter out
some interesting places in the code and then proceed with good-old manual code
review.

Okay, so now we've figured out some functions which return tainted data (in our
case, just `get_tainted_int`). We will now proceed to find patterns which match
our first criteria (calls to `memcpy` where the size argument is tainted).

We can do this with:

{% highlight scala %}
joern> val src = cpg.call.name("get_tainted_int")
val src: NodeSteps[Call] = io.shiftleft.semanticcpg.language.NodeSteps@719363e7

joern> val sink = cpg.call.name("memcpy").argument
sink: NodeSteps[Expression] = io.shiftleft.semanticcpg.language.NodeSteps@33fb7e39

joern> sink.reachableByFlows(src).p
res16: List[String] = List()
{% endhighlight %}

Hmm, so that didn't work...

This is because inter-procedural taint-analysis is not yet supported in the
open-source version. So we can do some more filtering.

We will look for functions where data from `get_tainted_int` reaches a call to
a function which then calls `memcpy` on it.

{% highlight scala %}
joern> val src = cpg.call.name("get_tainted_int") 
src: NodeSteps[Call] = io.shiftleft.semanticcpg.language.NodeSteps@d346b6e

joern> val sink = cpg.call.argument
sink: NodeSteps[Expression] = io.shiftleft.semanticcpg.language.NodeSteps@ba3095b

joern> sink.reachableByFlows(src).p
res19: List[String] = List(
  """______________________________________________________________________________________
| tracked                 | lineNumber| method| file                                  |
|=====================================================================================|
| get_tainted_int(fd)     | 21        | main  | /Users/jai/wd/tmp/vuln/overflow/main.c|
| sz = get_tainted_int(fd)| 21        | main  | /Users/jai/wd/tmp/vuln/overflow/main.c|
| copy(str, sz)           | 24        | main  | /Users/jai/wd/tmp/vuln/overflow/main.c|
""",
...
{% endhighlight %}

Great, so now we now that the `copy` function takes a tainted argument. Now we
will check if this argument reaches a call to `memcpy`.

{% highlight scala %}
joern> val src = cpg.method.name("copy").parameter.order(2)
src: NodeSteps[MethodParameterIn] = io.shiftleft.semanticcpg.language.NodeSteps@4477366d

joern> val sink = cpg.call.name("memcpy").argument.order(3)
sink: NodeSteps[Expression] = io.shiftleft.semanticcpg.language.NodeSteps@44ece267

joern> sink.reachableByFlows(src).p
res31: List[String] = List(
  """__________________________________________________________________________________
| tracked             | lineNumber| method| file                                  |
|=================================================================================|
| copy(char *s, int n)| 14        | copy  | /Users/jai/wd/tmp/vuln/overflow/main.c|
| memcpy(buf, s, n)   | 16        | copy  | /Users/jai/wd/tmp/vuln/overflow/main.c|
"""
)
{% endhighlight %}

That's great! We finally got our call to `memcpy`.

We can also do all of this in one-shot as follows:

{% highlight scala %}
def getFlow() = {
    val src = cpg.call.name("get_tainted_int")
    val sink = cpg.call

    val funcs = sink.whereNonEmpty(
        _.start.argument.reachableBy(src)
    )

    funcs.l.map(
        func => {
            val method = cpg.method.name(func.name)
            val src = method.parameter
            val sink = cpg.call.name("memcpy").argument.order(3)
            sink.reachableByFlows(src).p
        }
    ).filter(_.size > 0)
}
{% endhighlight %}

This gives us the same result:

{% highlight scala %}
joern> getFlow()
res68: List[List[String]] = List(
  List(
    """__________________________________________________________________________________
| tracked             | lineNumber| method| file                                  |
|=================================================================================|
| copy(char *s, int n)| 14        | copy  | /Users/jai/wd/tmp/vuln/overflow/main.c|
| memcpy(buf, s, n)   | 16        | copy  | /Users/jai/wd/tmp/vuln/overflow/main.c|
""",
...
{% endhighlight %}

The query for the second part is left as an exercise for the reader. If you are
able to write it, email me your solution at (`jai2.verma at outlook dot com`).

### Finding bugs in U-Boot

Okay, so the main aim of this post was to try our the CodeQL U-Boot challenge
using Joern.

The CodeQL U-Boot challenge is a tutorial on GitHub which has exercises for
learning the basics of CodeQL by finding real bugs (fixed) which were present
in the U-Boot codebase. So I already tried them out with CodeQL and my queries
are present on [GitHub here](https://github.com/jaiverma/codeql-uboot).

Before we get started, to generate the `cpg` for this, I checked out the `u-boot`
repository to commit `d0d07ba`. And then I ran `joern-parse` on the repository.

So the actual first step for the challenge was [step-3](https://github.com/jaiverma/codeql-uboot/issues/3).

For this challenge, we just had to find functions named `strcpy`.

To do this in CodeQL, we would do the following:

```codeql
import cpp

from Function f
where f.getName() = "strlen"
select f, "a function named strlen"
```

The `joern` query is also simple:

{% highlight scala %}
cpg.method.name("strlen").map(
    m => (m.name, m.location.filename, m.location.lineNumber.get)
).l
{% endhighlight %}

This gives us the following results:

```
res8: List[(String, String, Integer)] = List(
  ("strlen", "/Users/jai/wd/tmp/u-boot/lib/string.c", 264),
  ("strlen", "/Users/jai/wd/tmp/u-boot/board/gdsys/common/osd.c", 288),
  ("strlen", "/Users/jai/wd/tmp/u-boot/board/Synology/ds414/cmd_syno.c", 101),
  ("strlen", "/Users/jai/wd/tmp/u-boot/board/Synology/ds414/cmd_syno.c", 89),
  ("strlen", "/Users/jai/wd/tmp/u-boot/cmd/elf.c", 491),
  ("strlen", "/Users/jai/wd/tmp/u-boot/cmd/elf.c", 448),
  ("strlen", "/Users/jai/wd/tmp/u-boot/drivers/video/videomodes.c", 153),
  ("strlen", "/Users/jai/wd/tmp/u-boot/common/command.c", 408),
  ("strlen", "/Users/jai/wd/tmp/u-boot/common/command.c", 368),
  ("strlen", "/Users/jai/wd/tmp/u-boot/common/command.c", 335),
  ("strlen", "/Users/jai/wd/tmp/u-boot/common/command.c", 226),
  ("strlen", "/Users/jai/wd/tmp/u-boot/common/cli_readline.c", 562),
  ("strlen", "/Users/jai/wd/tmp/u-boot/common/cli_readline.c", 468),
  ("strlen", "/Users/jai/wd/tmp/u-boot/test/print_ut.c", 131)
)
```

[step-4](https://github.com/jaiverma/codeql-uboot/issues/5) is identical to
`step-3`, we just have to find methods named `memcpy` instead of `strcpy`.

For [step-5](https://github.com/jaiverma/codeql-uboot/issues/7), the aim is to
find macros with name `ntohs`, `ntohl`, `ntohll`.

Joern doesn't have a separate class for macros. We can just use `cpg.method` as
we did earlier.

[step-6](https://github.com/jaiverma/codeql-uboot/issues/9) is to find calls to
`memcpy`. 

To do this in CodeQL, we do the following:

```codeql
import cpp

from FunctionCall c
where
    c.getTarget().hasName("memcpy")
select c
```

We can do this in Joern as follows:

{% highlight scala %}
cpg.call.name("memcpy").map(
    m => (m.name, m.location.filename, m.location.lineNumber.get)
).l
{% endhighlight %}

This gives us the following results:

```
res20: List[(String, String, Integer)] = List(
  (
    "memcpy",
    "/Users/jai/wd/tmp/u-boot/lib/efi_selftest/efi_selftest_set_virtual_address_map.c",
    128
  ),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/arch/x86/cpu/broadwell/sdram.c", 145),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/arch/x86/cpu/broadwell/sdram.c", 144),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/soc/ti/k3-navss-ringacc.c", 824),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/soc/ti/k3-navss-ringacc.c", 806),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/fs/ubifs/tnc.c", 1659),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/ddr/fsl/interactive.c", 2071),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/ddr/fsl/interactive.c", 2063),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/ddr/fsl/interactive.c", 2057),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/ddr/fsl/interactive.c", 2051),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/drivers/ddr/fsl/interactive.c", 2045),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/fs/ubifs/tnc.c", 396),
  ("memcpy", "/Users/jai/wd/tmp/u-boot/fs/ubifs/tnc.c", 199),
```

For [step-7](https://github.com/jaiverma/codeql-uboot/issues/11), we want to
find invocations of the `ntoh*` macros. Again, since joern doesn't have a
separate class for macros, we can just filter for calls.

{% highlight scala %}
cpg.call.name("ntoh.*").map(
    m => (m.name, m.location.filename, m.location.lineNumber.get)
).l
{% endhighlight %}

[step-8](https://github.com/jaiverma/codeql-uboot/issues/13) also remains the
same.

[step-9](https://github.com/jaiverma/codeql-uboot/issues/15) is also very
simple. We want to get top-level expressions which contain a call to `ntoh`.

In Joern, we are good to go with just the callsites of `ntoh`.

[step-10](https://github.com/jaiverma/codeql-uboot/issues/17) is the main
query. Here we are finding callistes of `memcpy` where the size parameter is
reachable by `ntoh*`.

This is what the query looks like in CodeQL.

```codeql
/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation i|
            i.getMacro().getName().regexpMatch("ntoh(s|l|ll)") and
            this = i.getExpr()
        )
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "NetworkToMemFuncLength" }

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }

    override predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall f |
            f.getTarget().hasName("memcpy") and
            f.getArgument(2) = sink.asExpr()
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
```

This gives us 9 results which are all vulnerable. A major benefit of CodeQL is
that, unlike Joern, CodeQL supports inter-procedural taint analysis.

A similar query in joern looks like:

{% highlight scala %}
joern> val src = cpg.call.name("ntoh.*")
src: NodeSteps[Call] = io.shiftleft.semanticcpg.language.NodeSteps@771da67d

joern> val sink = cpg.call.name("memcpy").argument.order(3)
sink: NodeSteps[Expression] = io.shiftleft.semanticcpg.language.NodeSteps@64c8afbe

joern> sink.reachableByFlows(src).p
res4: List[String] = List(
  """_____________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method            | file                              |
|============================================================================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])                                                     | 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| rlen = ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])                                              | 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(nfs_path,\n\t\t       (uchar *)&(rpc_pkt.u.reply.data[2 + nfsv3_data_offset]),\n\t\t       rlen)| 647       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """_______________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                          | lineNumber| method            | file                              |
|======================================================================================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])                                                               | 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| rlen = ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])                                                        | 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(nfs_path + pathlen,\n\t\t       (uchar *)&(rpc_pkt.u.reply.data[2 + nfsv3_data_offset]),\n\t\t       rlen)| 642       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
"""
)
{% endhighlight %}

Okay so this is just giving us 2 calls, which is not bad at all.

Let's see if we can improve this, without spending any time in manual code
review.

So one thing we can search for is to see if any function returns data which is
tainted by `ntoh.*`. This won't be problematic like the `read` call, because
`ntoh*` returns a value, (unlike our example which used `read`). We would still
miss cases where a variable which is passed as a pointer argument is updated in
a function.

{% highlight scala %}
def getFlow() = {
    val src = cpg.call.name("ntoh(s|l|ll)")
    val sink = cpg.method.methodReturn
    sink.reachableByFlows(src).p
}
{% endhighlight %}

Okay so this gave us the following results:

{% highlight scala %}
joern> getFlow
res6: List[String] = List(
  """___________________________________________________________________________________________________________________________
| tracked                                                  | lineNumber| method        | file                              |
|==========================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])       | 695       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| rlen = ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])| 695       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return rlen;                                             | 707       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                                      | 655       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """________________________________________________________________________________________________________
| tracked                               | lineNumber| method        | file                              |
|=======================================================================================================|
| ntohl(rpc_pkt.u.reply.data[18])       | 688       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| rlen = ntohl(rpc_pkt.u.reply.data[18])| 688       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return rlen;                          | 707       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                   | 655       | nfs_read_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """_______________________________________________________________________________________________________________________________
| tracked                                                  | lineNumber| method            | file                              |
|==============================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])       | 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| rlen = ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])| 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return 0;                                                | 652       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                                      | 608       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """_______________________________________________________________________________________________________________________________
| tracked                                                  | lineNumber| method            | file                              |
|==============================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])       | 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| rlen = ntohl(rpc_pkt.u.reply.data[1 + nfsv3_data_offset])| 635       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| pathlen + rlen                                           | 645       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return 0;                                                | 652       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                                      | 608       | nfs_readlink_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """___________________________________________________________________________________________________________________
| tracked                                        | lineNumber| method          | file                              |
|==================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[1])                 | 571       | nfs_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| filefh3_length = ntohl(rpc_pkt.u.reply.data[1])| 571       | nfs_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return 0;                                      | 577       | nfs_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                            | 511       | nfs_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """__________________________________________________________________________________________________________________________
| tracked                                               | lineNumber| method          | file                              |
|=========================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[0])                        | 451       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| nfs_server_mount_port = ntohl(rpc_pkt.u.reply.data[0])| 451       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return 0;                                             | 458       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                                   | 431       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """____________________________________________________________________________________________________________________
| tracked                                         | lineNumber| method          | file                              |
|===================================================================================================================|
| ntohl(rpc_pkt.u.reply.data[0])                  | 454       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| nfs_server_port = ntohl(rpc_pkt.u.reply.data[0])| 454       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| return 0;                                       | 458       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| RET                                             | 431       | rpc_lookup_reply| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """___________________________________________________________________________________________________________________________
| tracked                               | lineNumber| method       | file                                                  |
|==========================================================================================================================|
| ntohs(ip->ip_len)                     | 515       | emaclite_recv| /Users/jai/wd/tmp/u-boot/drivers/net/xilinx_emaclite.c|
| length = ntohs(ip->ip_len)            | 515       | emaclite_recv| /Users/jai/wd/tmp/u-boot/drivers/net/xilinx_emaclite.c|
| length += ETHER_HDR_SIZE + ETH_FCS_LEN| 516       | emaclite_recv| /Users/jai/wd/tmp/u-boot/drivers/net/xilinx_emaclite.c|
| return length;                        | 538       | emaclite_recv| /Users/jai/wd/tmp/u-boot/drivers/net/xilinx_emaclite.c|
| RET                                   | 454       | emaclite_recv| /Users/jai/wd/tmp/u-boot/drivers/net/xilinx_emaclite.c|
"""
)
{% endhighlight %}

Strange, we got a couple of results which don't seem right. We have a couple of
flows which end with `return 0` which shouldn't show up with our query.

Anyway, let's work with what we have and see if we get anymore results.


