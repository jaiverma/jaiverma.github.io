---
layout: post
title: "Joern U-Boot"
date: 2020-08-03 17:30:00 +0530
categories: blog
---
`Note`: This is the second post about Joern and may have some overlap with the first one because I had started writing this one before the other one...

I've been playing around with a tool called [joern](https://github.com/ShiftLeftSecurity/joern) for some time now. Joern is a static analysis tool which is maintained by ShiftLeft. Joern uses something called code property graphs for representing a program.

The tool is written in Scala and has support for a powerful query language. Technical details are present on the official website [here](https://joern.io/docs/). Implementation details are present in [this](https://www.sec.cs.tu-bs.de/pubs/2014-ieeesp.pdf) research paper.

I feel that this tool is similar to [CodeQL](https://securitylab.github.com/tools/codeql). Some reasons I like Joern over CodeQL are:

- The query language for Joern is very easy to use and learn, whereas I found CodeQL to be much more difficult. I found Joern's query language to be much simpler that CodeQL.<br /><br />
- You don't have to build a project for use with Joern. Joern is bundled with a fuzzy source code parser which is able to generate a code property graph without actually building the code. This is both good and bad. The good part is that you can use Joern even when you don't have the full source code so you don't have to spend time in getting a working build (this is especially beneficial for embedded code bases). The bad part is that the accuracy of the queries decreases as compared to CodeQL.<br /><br />
- ~~One major disadvantage of Joern is, that it currently does not support inter-procedural taint-analysis (which is possible with CodeQL).~~ Joern now supports inter-procedural data-flow analysis!

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

We can print the location of calls in the program. `joern` considers assignment to be a call as well (a call to the `Operators.assignment` function). We can list these with:

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

We can also get flow from one operation to another. For example, if we want to see the trasformations on variable `x` from it's definition to the call to `printf`, we can do the following:

{% highlight scala %}
joern> val src = cpg.identifier.name("x") 
src: Traversal[Identifier] = Traversal

joern> val sink = cpg.call.name("printf").argument 
sink: Traversal[Expression] = Traversal

joern> sink.reachableByFlows(src).p 
res7: List[String] = List(
  """________________________________________________________________________________________
| tracked                | lineNumber| method| file                                     |
|=======================================================================================|
| x = add_one(x)         | 10        | main  | /home/jai/Documents/projects/vuln/main.c |
| printf("x is %d\n", x) | 11        | main  | /home/jai/Documents/projects/vuln/main.c |
""",
...
{% endhighlight %}

We can make this a little more generic. If we want to track flow from variables to calls to `printf` for any given method, we can do:

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
res9: List[String] = List(
  """________________________________________________________________________________________
| tracked                | lineNumber| method| file                                     |
|=======================================================================================|
| x = add_one(x)         | 10        | main  | /home/jai/Documents/projects/vuln/main.c |
| printf("x is %d\n", x) | 11        | main  | /home/jai/Documents/projects/vuln/main.c |
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

The program is vulnerable to a heap-based buffer overflow in the function `copy`. The parameter `n` is not validated to be less than the size of the buffer before the call to `memcpy`.

To discover this bug, we want to search for the following pattern:

- Calls to `memcpy` where the size argument is tainted (can be controlled by user input)<br /><br />
- Calls to `memcpy` where destination buffer size is not equal to the size parameter passed to `memcpy`.

To figure out which functions can taint variables, we have to do some manual code review. For instance, in our example, the function `get_tainted_int` is using the `read` function to read data from an untrusted file.

To decrease the effort in manual code review, we can first use Joern to filter which functions could be returning tainted data. Some of the functions which could taint variables include `read`, `ntohl`, `recv`, ...

We can get these functions with:

{% highlight scala %}
cpg.method.name("(read|ntohs|ntohl|recv)").caller.l.map(method => method.name)
res7: List[String] = List("get_tainted_int")
{% endhighlight %}

To do some more automated analysis, we could see if flow from the call to `read` to the return value of the function. This won't be applicable for functions which don't return a value, and instead update the value passed as a pointer argument to the function.

Also, I had some difficulties with Joern here, and there seem to be some inconsistencies. In the call to `read`, we are passing `&x` as second argument.

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

The problem I faced was that joern was not able to discover a path between the identifier `x`, and the call to `read`.

{% highlight scala %}
joern> val src = cpg.identifier.name("x") 
src: Traversal[Identifier] = Traversal

joern> val sink = cpg.call.name("read").argument(2) 
sink: Traversal[Expression] = Traversal

joern> sink.reachableByFlows(src).p 
res5: List[String] = List()
{% endhighlight %}

Anyway, we are still able to find a path from the local variables of the function to the return value.

{% highlight scala %}
joern> val src = cpg.method.name("get_tainted_int").local.referencingIdentifiers 
src: Traversal[Identifier] = Traversal

joern> val sink = cpg.method.name("get_tainted_int").methodReturn 
sink: Traversal[MethodReturn] = Traversal

joern> sink.reachableByFlows(src).p 
res8: List[String] = List(
  """_____________________________________________________________________________________
| tracked   | lineNumber| method          | file                                     |
|====================================================================================|
| return x; | 4         | get_tainted_int | /home/jai/Documents/projects/vuln/main.c |
| return x; | 4         | get_tainted_int | /home/jai/Documents/projects/vuln/main.c |
| int       | 1         | get_tainted_int | /home/jai/Documents/projects/vuln/main.c |
"""
)
{% endhighlight %}

So I would recommend a hybrid approach here. You can use Joern to filter out some interesting places in the code and then proceed with good-old manual code review.

Okay, so now we've figured out some functions which return tainted data (in our case, just `get_tainted_int`). We will now proceed to find patterns which match our first criteria (calls to `memcpy` where the size argument is tainted).

We can do this with:

{% highlight scala %}
joern> val src = cpg.call.name("get_tainted_int") 
src: Traversal[Call] = Traversal

joern> val sink = cpg.call.name("memcpy").argument(3) 
sink: Traversal[Expression] = Traversal

joern> sink.reachableByFlows(src).p 
res14: List[String] = List(
  """__________________________________________________________________________________________
| tracked                  | lineNumber| method| file                                     |
|=========================================================================================|
| get_tainted_int(fd)      | 14        | main  | /home/jai/Documents/projects/vuln/main.c |
| sz = get_tainted_int(fd) | 14        | main  | /home/jai/Documents/projects/vuln/main.c |
| malloc(sz)               | 15        | main  | /home/jai/Documents/projects/vuln/main.c |
| malloc(sz)               | 15        | main  | /home/jai/Documents/projects/vuln/main.c |
| * str = malloc(sz)       | 15        | main  | /home/jai/Documents/projects/vuln/main.c |
| copy(str, sz)            | 17        | main  | /home/jai/Documents/projects/vuln/main.c |
| copy(char *s, int n)     | 7         | copy  | /home/jai/Documents/projects/vuln/main.c |
| memcpy(buf, s, n)        | 9         | copy  | /home/jai/Documents/projects/vuln/main.c |
| memcpy(buf, s, n)        | 9         | copy  | /home/jai/Documents/projects/vuln/main.c |
| memcpy(buf, s, n)        | 9         | copy  | /home/jai/Documents/projects/vuln/main.c |
"""
)
{% endhighlight %}

~~Hmm, so that didn't work...~~ This works perfectly thanks to Joern's inter-procedural data-flow analysis.

~~This is because inter-procedural taint-analysis is not yet supported in the open-source version. So we can do some more filtering.~~

**The remaining part of this section is only applicable to versions of Joern prior to `v1.0.0`. We continue in the U-Boot section.**

As an exercise, we'll still try to do some manual data-flow analysis using intra-procedural building blocks. We will look for functions where data from `get_tainted_int` reaches a call to a function which then calls `memcpy` on it.

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

Great, so now we know that the `copy` function takes a tainted argument. Now we will check if this argument reaches a call to `memcpy`.

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

The query for the second part is left as an exercise for the reader. If you are able to write it, email me your solution at (`jai2.verma at outlook dot com`).

### Finding bugs in U-Boot

Okay, so the main aim of this post was to try our the CodeQL U-Boot challenge using Joern.

The CodeQL U-Boot challenge is a tutorial on GitHub which has exercises for learning the basics of CodeQL by finding real bugs (fixed) which were present in the U-Boot codebase. So I already tried them out with CodeQL and my queries are present on [GitHub here](https://github.com/jaiverma/codeql-uboot).

Before we get started, to generate the `cpg` for this, I checked out the `u-boot` repository to commit `d0d07ba`. And then I ran `joern-parse` on the repository.

So the actual first step for the challenge was [step-3](https://github.com/jaiverma/codeql-uboot/issues/3).

For this challenge, we just had to find functions named `strcpy`.

To do this in CodeQL, we would do the following:

{% highlight codeql %}
import cpp

from Function f
where f.getName() = "strlen"
select f, "a function named strlen"
{% endhighlight %}

The `joern` query is also simple:

{% highlight scala %}
cpg.method.name("strlen").map(
    m => (m.name, m.location.filename, m.location.lineNumber.get)
).l
{% endhighlight %}

This gives us the following results:

{% highlight scala %}
res1: List[(String, String, Integer)] = List(
  ("strlen", "/home/jai/Documents/projects/u-boot/arch/m68k/include/asm/string.h", 22),
  ("strlen", "/home/jai/Documents/projects/u-boot/arch/powerpc/include/asm/string.h", 20),
  ("strlen", "/home/jai/Documents/projects/u-boot/board/Synology/ds414/cmd_syno.c", 89),
  ("strlen", "/home/jai/Documents/projects/u-boot/board/Synology/ds414/cmd_syno.c", 101),
  ("strlen", "/home/jai/Documents/projects/u-boot/board/gdsys/common/osd.c", 288),
  ("strlen", "/home/jai/Documents/projects/u-boot/cmd/elf.c", 448),
  ("strlen", "/home/jai/Documents/projects/u-boot/cmd/elf.c", 491),
  ("strlen", "/home/jai/Documents/projects/u-boot/common/cli_readline.c", 468),
  ("strlen", "/home/jai/Documents/projects/u-boot/common/cli_readline.c", 562),
  ("strlen", "/home/jai/Documents/projects/u-boot/common/command.c", 226),
  ("strlen", "/home/jai/Documents/projects/u-boot/common/command.c", 335),
  ("strlen", "/home/jai/Documents/projects/u-boot/common/command.c", 368),
  ("strlen", "/home/jai/Documents/projects/u-boot/common/command.c", 408),
  ("strlen", "/home/jai/Documents/projects/u-boot/drivers/video/videomodes.c", 153),
  ("strlen", "/home/jai/Documents/projects/u-boot/include/linux/string.h", 74),
  ("strlen", "/home/jai/Documents/projects/u-boot/lib/string.c", 264),
  ("strlen", "/home/jai/Documents/projects/u-boot/test/print_ut.c", 131)
)
{% endhighlight %}

[step-4](https://github.com/jaiverma/codeql-uboot/issues/5) is identical to `step-3`, we just have to find methods named `memcpy` instead of `strcpy`.

For [step-5](https://github.com/jaiverma/codeql-uboot/issues/7), the aim is to find macros with name `ntohs`, `ntohl`, `ntohll`.

Joern doesn't have a separate class for macros. We can just use `cpg.method` as we did earlier.

[step-6](https://github.com/jaiverma/codeql-uboot/issues/9) is to find calls to `memcpy`. 

To do this in CodeQL, we do the following:

{% highlight codeql %}
import cpp

from FunctionCall c
where
    c.getTarget().hasName("memcpy")
select c
{% endhighlight %}

We can do this in Joern as follows:

{% highlight scala %}
cpg.call.name("memcpy").map(
    m => (m.name, m.location.filename, m.location.lineNumber.get)
).l
{% endhighlight %}

This gives us the following results:

{% highlight scala %}
joern> cpg.call.name("memcpy").map(
           m => (m.name, m.location.filename, m.location.lineNumber.get)
       ).l 
res2: List[(String, String, Integer)] = List(
  ("memcpy", "/home/jai/Documents/projects/u-boot/api/api.c", 667),
  ("memcpy", "/home/jai/Documents/projects/u-boot/api/api_net.c", 65),
  ("memcpy", "/home/jai/Documents/projects/u-boot/arch/arc/lib/relocate.c", 24),
  ("memcpy", "/home/jai/Documents/projects/u-boot/arch/arc/lib/relocate.c", 91),
  ("memcpy", "/home/jai/Documents/projects/u-boot/arch/arc/lib/relocate.c", 130),
  ("memcpy", "/home/jai/Documents/projects/u-boot/arch/arm/cpu/arm926ejs/mxs/spl_boot.c", 105),
  ("memcpy", "/home/jai/Documents/projects/u-boot/arch/arm/cpu/armv7/virt-v7.c", 58),
...
{% endhighlight %}

For [step-7](https://github.com/jaiverma/codeql-uboot/issues/11), we want to find invocations of the `ntoh*` macros. Again, since joern doesn't have a separate class for macros, we can just filter for calls.

{% highlight scala %}
cpg.call.name("ntoh.*").map(
    m => (m.name, m.location.filename, m.location.lineNumber.get)
).l
{% endhighlight %}

[step-8](https://github.com/jaiverma/codeql-uboot/issues/13) also remains the same.

[step-9](https://github.com/jaiverma/codeql-uboot/issues/15) is also very simple. We want to get top-level expressions which contain a call to `ntoh`.

In Joern, we are good to go with just the callsites of `ntoh`.

[step-10](https://github.com/jaiverma/codeql-uboot/issues/17) is the main query. Here we are finding callistes of `memcpy` where the size parameter is reachable by `ntoh*`.

This is what the query looks like in CodeQL.

{% highlight codeql %}
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
{% endhighlight %}

This gives us 9 results which are all vulnerable. ~~A major benefit of CodeQL is that, unlike Joern, CodeQL supports inter-procedural taint analysis.~~

We can look for the same thing with Joern with the following query:

{% highlight scala %}
val src = cpg.call.name("ntoh.*")
val sink = cpg.call.name("memcpy").argument(3)
sink.reachableByFlows(src).p
{% endhighlight %}

This gives us 62 results! Some of them are:

```
res6: List[String] = List(
  """______________________________________________________________________________________________________________________________________
| tracked                                              | lineNumber| method           | file                                          |
|=====================================================================================================================================|
| ntohs(ip->ip_off)                                    | 906       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| ip_off = ntohs(ip->ip_off)                           | 906       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| ip_off & IP_OFFS                                     | 910       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| ip_off & IP_OFFS                                     | 910       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| offset8 =  (ip_off & IP_OFFS)                        | 910       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| payload + offset8                                    | 911       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| thisfrag = payload + offset8                         | 911       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| h >= thisfrag                                        | 963       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| h >= thisfrag                                        | 985       | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| (uchar *)thisfrag                                    | 1009      | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
| memcpy((uchar *)thisfrag, indata + IP_HDR_SIZE, len) | 1009      | __net_defragment | /home/jai/Documents/projects/u-boot/net/net.c |
""",
  """____________________________________________________________________________________________________________________________________________________
| tracked                                                       | lineNumber| method           | file                                               |
|===================================================================================================================================================|
| ntohs(net_our_vlan)                                           | 1419      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| myvlanid = ntohs(net_our_vlan)                                | 1419      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| myvlanid == (ushort)-1                                        | 1420      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| myvlanid & VLAN_IDMASK                                        | 1423      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| myvlanid & VLAN_IDMASK                                        | 1423      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| myvlanid & VLAN_IDMASK                                        | 1423      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| (myvlanid & VLAN_IDMASK) == VLAN_NONE                         | 1423      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| int                                                           | 1414      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| net_eth_hdr_size(void)                                        | 1414      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| int                                                           | 1414      | net_eth_hdr_size | /home/jai/Documents/projects/u-boot/net/net.c      |
| net_eth_hdr_size()                                            | 137       | fastboot_send    | /home/jai/Documents/projects/u-boot/net/fastboot.c |
| net_tx_packet + net_eth_hdr_size() + IP_UDP_HDR_SIZE          | 137       | fastboot_send    | /home/jai/Documents/projects/u-boot/net/fastboot.c |
| packet = net_tx_packet + net_eth_hdr_size() + IP_UDP_HDR_SIZE | 137       | fastboot_send    | /home/jai/Documents/projects/u-boot/net/fastboot.c |
| memcpy(packet, &response_header, sizeof(response_header))     | 150       | fastboot_send    | /home/jai/Documents/projects/u-boot/net/fastboot.c |
| sizeof(response_header)                                       | 196       | fastboot_send    | /home/jai/Documents/projects/u-boot/net/fastboot.c |
""",
  """___________________________________________________________________________________________________________________________________________
| tracked                                                   | lineNumber| method           | file                                          |
|==========================================================================================================================================|
| ntohs(et->et_protlen)                                     | 1458      | net_update_ether | /home/jai/Documents/projects/u-boot/net/net.c |
| protlen = ntohs(et->et_protlen)                           | 1458      | net_update_ether | /home/jai/Documents/projects/u-boot/net/net.c |
| protlen == PROT_VLAN                                      | 1459      | net_update_ether | /home/jai/Documents/projects/u-boot/net/net.c |
| protlen > 1514                                            | 1464      | net_update_ether | /home/jai/Documents/projects/u-boot/net/net.c |
| protlen > 1514                                            | 1464      | net_update_ether | /home/jai/Documents/projects/u-boot/net/net.c |
| int                                                       | 1452      | net_update_ether | /home/jai/Documents/projects/u-boot/net/net.c |
| net_update_ether(et, et->et_src, PROT_ARP)                | 165       | arp_receive      | /home/jai/Documents/projects/u-boot/net/arp.c |
| eth_hdr_size = net_update_ether(et, et->et_src, PROT_ARP) | 165       | arp_receive      | /home/jai/Documents/projects/u-boot/net/arp.c |
| eth_hdr_size + ARP_HDR_SIZE                               | 186       | arp_receive      | /home/jai/Documents/projects/u-boot/net/arp.c |
""",
  """__________________________________________________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                                             | lineNumber| method                 | file                                                 |
|=================================================================================================================================================================================================================================|
| ntohs(arp->ar_pro)                                                                                                                  | 251       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| ntohs(arp->ar_op)                                                                                                                   | 252       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| debug_cond(DEBUG_INT_STATE, "%s recv arp type=%d, op=%d,\n",\n\t\t   eth_get_name(), ntohs(arp->ar_pro),\n\t\t   ntohs(arp->ar_op)) | 250       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| debug_cond(DEBUG_INT_STATE, "\tsource=%pM %pI4\n",\n\t\t   &arp->ar_sha,\n\t\t   &arp->ar_spa)                                      | 253       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| debug_cond(DEBUG_INT_STATE, "\tsource=%pM %pI4\n",\n\t\t   &arp->ar_sha,\n\t\t   &arp->ar_spa)                                      | 253       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| memcmp(&arp->ar_sha, net_ethaddr, ARP_HLEN)                                                                                         | 270       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| memcmp(&arp->ar_sha, net_ethaddr, ARP_HLEN)                                                                                         | 283       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| arp_raw_request(ip, net_ethaddr, ip)                                                                                                | 317       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| arp_raw_request(struct in_addr source_ip, const uchar *target_ethaddr, struct in_addr target_ip)                                    | 51        | arp_raw_request        | /home/jai/Documents/projects/u-boot/net/arp.c        |
| memcpy(&arp->ar_tha, target_ethaddr, ARP_HLEN)                                                                                      | 75        | arp_raw_request        | /home/jai/Documents/projects/u-boot/net/arp.c        |
""",
  """__________________________________________________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                                             | lineNumber| method                 | file                                                 |
|=================================================================================================================================================================================================================================|
| ntohs(arp->ar_op)                                                                                                                   | 252       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| debug_cond(DEBUG_INT_STATE, "%s recv arp type=%d, op=%d,\n",\n\t\t   eth_get_name(), ntohs(arp->ar_pro),\n\t\t   ntohs(arp->ar_op)) | 250       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| debug_cond(DEBUG_INT_STATE, "\tsource=%pM %pI4\n",\n\t\t   &arp->ar_sha,\n\t\t   &arp->ar_spa)                                      | 253       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| debug_cond(DEBUG_INT_STATE, "\tsource=%pM %pI4\n",\n\t\t   &arp->ar_sha,\n\t\t   &arp->ar_spa)                                      | 253       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| memcmp(&arp->ar_sha, net_ethaddr, ARP_HLEN)                                                                                         | 270       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| memcmp(&arp->ar_sha, net_ethaddr, ARP_HLEN)                                                                                         | 283       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| arp_raw_request(ip, net_ethaddr, ip)                                                                                                | 317       | link_local_receive_arp | /home/jai/Documents/projects/u-boot/net/link_local.c |
| arp_raw_request(struct in_addr source_ip, const uchar *target_ethaddr, struct in_addr target_ip)                                    | 51        | arp_raw_request        | /home/jai/Documents/projects/u-boot/net/arp.c        |
| memcpy(&arp->ar_tha, target_ethaddr, ARP_HLEN)                                                                                      | 75        | arp_raw_request        | /home/jai/Documents/projects/u-boot/net/arp.c        |
""",
...
```

The complete output of the query can be found here: [https://gist.github.com/jaiverma/aac963869ee576bd80dd683ec25976d3](https://gist.github.com/jaiverma/aac963869ee576bd80dd683ec25976d3)

Of-course, not all of these results are vulnerable. The majority of them are safe. Joern's argument level granularity is not always accurate, so if tainted data reaches any of the arguments of a function marked as a sink, it will show that data-flow in the results. This issue is tracked here: [https://github.com/ShiftLeftSecurity/codepropertygraph/issues/729](https://github.com/ShiftLeftSecurity/codepropertygraph/issues/729).

There are different strategies that different static analysis tools use for tracking taint which gives us different kinds of behaviour. For example, some tools stop tracking taint if there is an `if` condition to check bounds of a tainted variable. CodeQl supports value-set analysis which lets you specify lower and upper bounds of a variable in a query. Right now, Joern doesn't lose taint when a tainted variable goes through an `if` condition. This is a complex scenario to handle and different tools handle this in different ways.

-----------------------------------------------------------

**The reamining part of this post is only applicable to version of Joern prior to `v1.0.0`. Newer versions moved to a different API, and later on introduced inter-procedural data-flow analysis!**

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

Okay so this is just giving us 2 calls, which is not bad at all. Here are the results which CodeQL gives us:

{% highlight txt %}
1. Network byte swap flows to memcpy	netconsole.c:161:37
2. Network byte swap flows to memcpy	netconsole.c:164:34
3. Network byte swap flows to memcpy	net.c:1009:50
4. Network byte swap flows to memcpy	nfs.c:644:10
5. Network byte swap flows to memcpy	nfs.c:649:10
6. Network byte swap flows to memcpy	nfs.c:574:44
7. Network byte swap flows to memcpy	nfs.c:106:20
8. Network byte swap flows to memcpy	nfs.c:106:20
9. Network byte swap flows to memcpy	ping.c:108:25
{% endhighlight %}

Our Joern results correspond to number 4 and number 5. Let's see if we can improve this, without spending any time in manual code review.

One thing that we can look for is, places where data tainted with `ntoh` is passed to a function as an argument. Then this argument is used somewhere as an argument to `memcpy`. We'll just look for one layer of such calls, although we can improve our query by recursively searching for this pattern.

{% highlight scala %}
def getFlow() = {
    val src = cpg.call.name("ntoh(s|l|ll)")
    val sink = cpg.call

    val callsites = sink.whereNonEmpty {
        _.start.argument.reachableBy(src)
    }

    val newSrc = callsites.method.parameter
    val newSink = cpg.call.name("memcpy").argument.order(3)
    newSink.reachableByFlows(newSrc).p
}
{% endhighlight %}

So since `u-boot` is a big project with a large codebase, this query doesn't seem to run in a reasonable amount of time (I'm running this on a machine from 2013 with 8 GB RAM and an i5 processor). So I'll try to use a more systematic approach which should give us our results quicker, and we'll also be able to tell if our query is actully making any progress or not.

{% highlight scala %}
def getFlow(methodName: String) = {
    val src = cpg.method.name(methodName).ast.isCallTo("ntoh(s|l|ll)")
    val sink = cpg.method.name(methodName).ast.isCall

    val methods = sink.whereNonEmpty(
        _.start.argument.reachableBy(src))
        .filterNot(_.isCallTo("<operator>.*"))
        .callee
        .name

    methods.foreach(m => {
        println(s"Looking in $m ...")
        val src = cpg.method.name(m).parameter
        val sink = cpg.method.name(m)
            .ast
            .isCallTo("memcpy")
            .argument
            .order(3)
        println(sink.reachableByFlows(src).p)
    })
}
{% endhighlight %}

What we've done here is that we've divided our computation into smaller chunks. With this query, we can apply this to each function in the codebase and get quicker and gradual results. When we apply this function to `net_process_received_packet`, we get a result!

{% highlight scala %}
joern> getFlow("net_process_received_packet")
Looking in debug_cond ...
List()
Looking in ntohs ...
List()
Looking in ntohs ...
List()
Looking in debug_cond ...
List()
Looking in debug_cond ...
List()
Looking in nc_input_packet ...
List(_________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len = sizeof(input_buffer) - input_size                                                                | 150       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| chunk = len                                                                                            | 156       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(input_buffer + end, pkt, chunk)                                                                 | 164       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
, _________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| chunk = len                                                                                            | 156       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(input_buffer + end, pkt, chunk)                                                                 | 164       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
, _________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(input_buffer + end, pkt, chunk)                                                                 | 164       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
, _________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len = sizeof(input_buffer) - input_size                                                                | 150       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len - chunk                                                                                            | 161       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
, _________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len - chunk                                                                                            | 161       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
)
Looking in *udp_packet_handler ...
java.util.regex.PatternSyntaxException: Dangling meta character '*' near index 0
*udp_packet_handler
^
  java.util.regex.Pattern.error(Pattern.java:1969)
  java.util.regex.Pattern.sequence(Pattern.java:2137)
  java.util.regex.Pattern.expr(Pattern.java:2010)
  java.util.regex.Pattern.compile(Pattern.java:1702)
  java.util.regex.Pattern.<init>(Pattern.java:1352)
  java.util.regex.Pattern.compile(Pattern.java:1028)
  io.shiftleft.codepropertygraph.predicates.Text.textRegex(Text.java:31)
  io.shiftleft.semanticcpg.language.types.propertyaccessors.StringPropertyAccessors.stringPropertyFilter(StringPropertyAccessors.scala:15)
  io.shiftleft.semanticcpg.language.types.propertyaccessors.StringPropertyAccessors.stringPropertyFilter$(StringPropertyAccessors.scala:14)
  io.shiftleft.semanticcpg.language.types.propertyaccessors.NameAccessors.stringPropertyFilter(NameAccessors.scala:8)
  io.shiftleft.semanticcpg.language.types.propertyaccessors.NameAccessors.name(NameAccessors.scala:21)
  ammonite.$sess.cmd39$.$anonfun$getFlow$3(cmd39.sc:13)
  ammonite.$sess.cmd39$.$anonfun$getFlow$3$adapted(cmd39.sc:11)
  scala.collection.IterableOnceOps.foreach(IterableOnce.scala:576)
  scala.collection.IterableOnceOps.foreach$(IterableOnce.scala:574)
  overflowdb.traversal.Traversal.foreach(Traversal.scala:16)
  ammonite.$sess.cmd39$.getFlow(cmd39.sc:11)
  ammonite.$sess.cmd40$.<clinit>(cmd40.sc:1)
{% endhighlight %}

The reason we see a failure in the end is because of the function name `*udp_packet_handler` (which is a function poitner) is interpreted as an incomplete regex. No worries, we will ignore this because we got our result for `nc_input_packet`. This result corresponds to number 1 and number 2 of the CodeQL output.

Similarly, when we run this query for `nfs_read_reply`, we get the following result:

{% highlight scala %}
joern> getFlow("nfs_read_reply")
Looking in store_block ...
List(____________________________________________________________________________________________________________________
| tracked                                             | lineNumber| method     | file                               |
|===================================================================================================================|
| store_block(int block, uchar *src, unsigned int len)| 143       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
| map_sysmem(store_addr, len)                         | 180       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
| ptr = map_sysmem(store_addr, len)                   | 180       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
| memcpy(ptr, src, len)                               | 181       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
, ____________________________________________________________________________________________________________________
| tracked                                             | lineNumber| method     | file                               |
|===================================================================================================================|
| store_block(int block, uchar *src, unsigned int len)| 143       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
| memcpy(ptr, src, len)                               | 181       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
, ____________________________________________________________________________________________________________________
| tracked                                             | lineNumber| method     | file                               |
|===================================================================================================================|
| store_block(int block, uchar *src, unsigned int len)| 143       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
| memcpy(ptr, src, len)                               | 181       | store_block| /Users/jai/wd/tmp/u-boot/net/tftp.c|
, _____________________________________________________________________________________________________________________
| tracked                                               | lineNumber| method     | file                              |
|====================================================================================================================|
| store_block(uchar *src, unsigned offset, unsigned len)| 81        | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| load_addr + offset                                    | 104       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| map_sysmem(load_addr + offset, len)                   | 104       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| *ptr = map_sysmem(load_addr + offset, len)            | 104       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(ptr, src, len)                                 | 106       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
, _____________________________________________________________________________________________________________________
| tracked                                               | lineNumber| method     | file                              |
|====================================================================================================================|
| store_block(uchar *src, unsigned offset, unsigned len)| 81        | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| map_sysmem(load_addr + offset, len)                   | 104       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| *ptr = map_sysmem(load_addr + offset, len)            | 104       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(ptr, src, len)                                 | 106       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
, _____________________________________________________________________________________________________________________
| tracked                                               | lineNumber| method     | file                              |
|====================================================================================================================|
| store_block(uchar *src, unsigned offset, unsigned len)| 81        | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(ptr, src, len)                                 | 106       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
, _____________________________________________________________________________________________________________________
| tracked                                               | lineNumber| method     | file                              |
|====================================================================================================================|
| store_block(uchar *src, unsigned offset, unsigned len)| 81        | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(ptr, src, len)                                 | 106       | store_block| /Users/jai/wd/tmp/u-boot/net/nfs.c|
)
{% endhighlight %}

This corresponds to number 7 and number 8 of the CodeQL output.

Okay, now let's try to go for more than 1 layer of taint flow. There is a cool feature in Joern which I recently learned of, which allows you to modify the CPG and add custom labels to the CPG nodes. What we'll try to do now is, for each call to `ntoh`, we'll label all function parameters which are reachable by this call, and we'll do this recurisvely.

{% highlight scala %}
import scala.collection.immutable.HashSet

def labelVuln(func: String, done: HashSet[String]) : Unit = {
    if (done(func)) return
    else {
        val candidateFuncs = cpg.method.name(func)
            .caller
            .name
            .l
            .distinct

        for (f <- candidateFuncs) {
            println(s"Working on $f ...")

            def src = cpg.method.name(f)
                .ast
                .isCallTo(func)

            def sink = cpg.method.name(f)
                .ast
                .isCall

            def toTag = sink.whereNonEmpty(
                _.start.argument.reachableBy(src))
                .filterNot(_.isCallTo("<operator>.*"))

            if (!toTag.isEmpty) {
                println("found a path!");
                toTag.callee
                    .parameter
                    .newTagNode("tainted-source")
                    .store

                labelVuln(f, done + func)
            }
            else
                println("no path found...")
        }
    }
}
{% endhighlight %}

So with this, we are tagging all nodes which we believe are reachable by `ntoh`. This may not be a hundred percent accurate, but we can manually filter out the results which seem valid to us. We can call this function as:

{% highlight scala %}
joern> labelVuln("ntohs", HashSet())
Working on fastboot_handler ...
no path found...
Working on tftp_handler ...
found a path!
Working on link_local_receive_arp ...
found a path!
Working on efi_net_receive ...
no path found...
Working on dns_handler ...
no path found...
Working on cdp_receive ...
found a path!
Working on net_process_received_packet ...
found a path!
Working on tsec_recv ...
found a path!
Working on fec_recv ...
found a path!
Working on armdfec_recv ...
no path found...
Working on usb_eth_recv ...
no path found...
Working on r8152_recv ...
found a path!
...
{% endhighlight %}

Once we have tagged all possible tainted parameters, we can run a quick query to find data flow.

{% highlight scala %}
joern> cpg.call.name("memcpy").argument.order(3).reachableByFlows(cpg.tag("tainted-source").parameter).p
res28: List[String] = List(
  """_____________________________________________________________________________________________
| tracked                    | lineNumber| method        | file                              |
|============================================================================================|
| nfs_lookup_req(char *fname)| 316       | nfs_lookup_req| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(p, fname, fnamelen) | 347       | nfs_lookup_req| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """_____________________________________________________________________________________________
| tracked                    | lineNumber| method        | file                              |
|============================================================================================|
| nfs_lookup_req(char *fname)| 316       | nfs_lookup_req| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| memcpy(p, fname, fnamelen) | 334       | nfs_lookup_req| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """___________________________________________________________________________________________________________________________
| tracked                                                         | lineNumber| method | file                              |
|==========================================================================================================================|
| rpc_req(int rpc_prog, int rpc_proc, uint32_t *data, int datalen)| 173       | rpc_req| /Users/jai/wd/tmp/u-boot/net/nfs.c|
| datalen*sizeof(uint32_t)                                        | 202       | rpc_req| /Users/jai/wd/tmp/u-boot/net/nfs.c|
""",
  """_________________________________________________________________________________________________________________________
| tracked                                 | lineNumber| method        | file                                             |
|========================================================================================================================|
| nc_send_packet(const char *buf, int len)| 171       | nc_send_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(pkt, buf, len)                   | 213       | nc_send_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """_________________________________________________________________________________________________________________________
| tracked                                 | lineNumber| method        | file                                             |
|========================================================================================================================|
| nc_send_packet(const char *buf, int len)| 171       | nc_send_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(pkt, buf, len)                   | 213       | nc_send_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """_________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len = sizeof(input_buffer) - input_size                                                                | 150       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| chunk = len                                                                                            | 156       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(input_buffer + end, pkt, chunk)                                                                 | 164       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """_________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| chunk = len                                                                                            | 156       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(input_buffer + end, pkt, chunk)                                                                 | 164       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """_________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| memcpy(input_buffer + end, pkt, chunk)                                                                 | 164       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """_________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len = sizeof(input_buffer) - input_size                                                                | 150       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len - chunk                                                                                            | 161       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """_________________________________________________________________________________________________________________________________________________________________________________________
| tracked                                                                                                | lineNumber| method         | file                                             |
|========================================================================================================================================================================================|
| nc_input_packet(uchar *pkt, struct in_addr src_ip, unsigned dest_port, unsigned src_port, unsigned len)| 134       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
| len - chunk                                                                                            | 161       | nc_input_packet| /Users/jai/wd/tmp/u-boot/drivers/net/netconsole.c|
""",
  """___________________________________________________________________________________________________________________________________
| tracked                                                             | lineNumber| method     | file                              |
|==================================================================================================================================|
| arp_receive(struct ethernet_hdr *et, struct ip_udp_hdr *ip, int len)| 123       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
| net_update_ether(et, et->et_src, PROT_ARP)                          | 165       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
| eth_hdr_size = net_update_ether(et, et->et_src, PROT_ARP)           | 165       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
| eth_hdr_size + ARP_HDR_SIZE                                         | 186       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
""",
  """___________________________________________________________________________________________________________________________________
| tracked                                                             | lineNumber| method     | file                              |
|==================================================================================================================================|
| arp_receive(struct ethernet_hdr *et, struct ip_udp_hdr *ip, int len)| 123       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
| net_update_ether(et, et->et_src, PROT_ARP)                          | 165       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
| eth_hdr_size = net_update_ether(et, et->et_src, PROT_ARP)           | 165       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
| eth_hdr_size + ARP_HDR_SIZE                                         | 186       | arp_receive| /Users/jai/wd/tmp/u-boot/net/arp.c|
"""
)
{% endhighlight %}

Okay great, we got some results! But unfortunately, most of these aren't vulnerabilities. Only the results for `nc_input_packet` are real bugs and we've already found them above. The reason we are seeing the other results, is that the tainted data is being propagated indirectly to other variables. Also, we do not have argument specific granularity in our query which leads to these results.

Okay, so I'm ending this post here. Unfortunately, we were unable to find results 3, 6 and 9. 3 and 6 were pretty straightforward, and should have been found with Joern. 9 was a little trickier because taint spanned through multiple functions before reaching `memcpy`. If you are able to write a query to find these bugs, please email me your solutions!

So we say some pretty neat features which Joern supports. In the next post I'll try to describe my approach in finding 0-days with Joern! See you next time...
