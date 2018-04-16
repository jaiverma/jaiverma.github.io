---
layout: post
title: "Winning Minesweeper"
date: 2018-04-16 14:16:00 +0530
categories: blog
---
I recently saw a tweet by [Osanda Malith](https://twitter.com/OsandaMalith) about [hacking Minesweeper on Windows](https://osandamalith.com/2018/04/07/haxing-minesweeper/#more-2790), which got me motivated to do something similar for iOS. Since I had never won a game of Minesweeper before, I decided that cheating at it was the way to go. This post will cover how I reverse engineered a Minesweeper app for iOS and will delve into the various technical aspects of iOS reverse engineering on both a Jailbroken and non-Jailbroken iPhone. So if you're interested in reverse engineering or game hacking, read on!

The app I targeted is [Minesweeper Classic 2](https://itunes.apple.com/us/app/minesweeper-classic-2/id348787472). The devices used were a jailbroken iPhone 5S running iOS 10.2 and a non-jailbroken iPhone 7 running iOS 11.2.1. All the companion code for this post can be found [here](https://github.com/jaiverma/MineHacker).

### Static Analysis

I downloaded the application on a jailbroken iPhone running iOS 10.2 and retrieved the decrypted `ipa` using [Clutch](https://github.com/KJCracks/Clutch). With, the decrypted binary, further analysis can be done using a disassembler such as IDA Pro.

{% highlight shell_session %}
Jai-s-iPhone:~/bin root# ./Clutch-2.0.4-Debug -d com.libertyforone.minesweeperclassic2
Zipping MinesweeperClassic2.app
ASLR slide: 0x1000d8000
Dumping <MinesweeperClassic2NotificationServiceExtension> (arm64)
Patched cryptid (64bit segment)
Writing new checksum
Dumping <GoogleToolboxForMac> arm64
Dumping <leveldb> arm64
Successfully dumped framework GoogleToolboxForMac!
Child exited with status 0
Successfully dumped framework leveldb!
Child exited with status 0
Dumping <nanopb> arm64
Dumping <PureLayout> arm64
Successfully dumped framework nanopb!
Child exited with status 0
Successfully dumped framework PureLayout!
Child exited with status 0
Dumping <Protobuf> arm64
Successfully dumped framework Protobuf!
Child exited with status 0
ASLR slide: 0x100058000
Dumping <MinesweeperClassic2> (arm64)
Patched cryptid (64bit segment)
Dumping <MoPub> arm64
Successfully dumped framework MoPub!
Child exited with status 0
Writing new checksum
Zipping GoogleToolboxForMac.framework
Zipping MoPub.framework
Zipping Protobuf.framework
Zipping PureLayout.framework
Zipping leveldb.framework
Zipping nanopb.framework
Zipping MinesweeperClassic2NotificationServiceExtension.appex
DONE: /private/var/mobile/Documents/Dumped/com.libertyforone.minesweeperclassic2-iOS9.0-(Clutch-2.0.4 DEBUG)-2.ipa
Finished dumping com.libertyforone.minesweeperclassic2 in 10.8 seconds
{% endhighlight %}

`-[MinesweeperViewController startNewGame]` is the function responsible for initialising the game. The `MinesweeperViewController` has a member named `board` which is a `BoardView` which stores the game grid as a 2D integer array. `startNewGame` initialises this grid using `-[BoardView setGrid: x: y: ]`. All cells of the 2D array which hold bombs are initialised with the number `17` and the rest are set to `16`.

{% highlight c %}
void __cdecl -[MinesweeperViewController startNewGame](MinesweeperViewController *self, SEL a2)
{
  ...

  for ( i = 0; i < (signed int)-[BoardView width](v24->board, "width"); ++i )
  {
    for ( j = 0; j < (signed int)-[BoardView height](v24->board, "height"); ++j )
      -[BoardView setGrid:x:y:](v24->board, "setGrid:x:y:", 16LL, (unsigned int)i, (unsigned int)j);
  }

  ...

  v7 = time(0LL);
  srand(v7);
  for ( k = 0; k < v24->minecount; ++k )
  {
    v8 = (double)(signed int)-[BoardView height](v24->board, "height");
    v9 = v8 * (double)(signed int)-[BoardView width](v24->board, "width");
    v10 = v9 * (double)rand();
    v21 = (signed int)(v10 / 2147483650.0);
    v11 = (signed int)(v10 / 2147483650.0);
    v12 = v24->board;
    v13 = (unsigned __int64)-[BoardView width](v24->board, "width");
    v14 = v11 - v11 / v13 * v13;
    v15 = (unsigned __int64)-[BoardView width](v24->board, "width");
    if ( (unsigned int)-[BoardView gridAtx:y:](v12, "gridAtx:y:", v14, (unsigned int)(v21 / v15)) == 17 )
      --k;
    v16 = v24->board;
    v17 = (unsigned __int64)-[BoardView width](v24->board, "width");
    v18 = v21 - v21 / v17 * v17;
    v19 = (unsigned __int64)-[BoardView width](v24->board, "width");
    -[BoardView setGrid:x:y:](v16, "setGrid:x:y:", 17LL, v18, (unsigned int)(v21 / v19));
  }

  ...
}
{% endhighlight %}

Accordingly, all we have to do now is select the cells in the grid which have the value 16, and avoid all the cells with the value 17. It would be a great aid if we could somehow highlight all the cells with bombs.

The `-[BoardView setGrid: x: y: ]` is responsible for highlighting the cell at index (x,y) with the appropriate image.

{% highlight c %}
void __cdecl -[BoardView setGrid:x:y:](BoardView *self, SEL a2, int a3, int x, int y)
{
  double v5; // d3
  BoardView *v6; // [xsp+48h] [xbp-8h]

  v6 = self;
  if ( self->grid[x][y] != a3 )
  {
    self->grid[x][y] = a3;
    v5 = self->squareSize;
    ...
    objc_msgSend(v6, "setNeedsDisplayInRect:");
  }
}
{% endhighlight %}


Usage of this function by the app can be traced with [Frida](http://frida.re/) which is an amazing dynamic instrumentation toolkit.

{% highlight shell_session %}
(ios) jai@Acheron ~ $ frida-trace -U -m "-[BoardView setGrid:x:y:]" -n MinesweeperClassic2
Instrumenting functions...
-[BoardView setGrid:x:y:]: Auto-generated handler at "/Users/jai/__handlers__/__BoardView_setGrid_x_y__.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0x403 */
  4543 ms  -[BoardView setGrid:0x14 x:0x0 y:0x0]
  4795 ms  -[BoardView setGrid:0xd x:0x0 y:0x0]
  7884 ms  -[BoardView setGrid:0x12 x:0x3 y:0x1]
  7885 ms  -[BoardView setGrid:0x2 x:0x3 y:0x1]
 10671 ms  -[BoardView setGrid:0x12 x:0x4 y:0x1]

...

^C%
{% endhighlight %}

This is the trace of `setGrid:x:y:` being called on various events including displaying a flag, a number and a bomb. So this function can be utilised to highlight all cells which have bombs present by checking the grid.

{:refdef: style="text-align: center;"}
![Minesweeper]({{"/assets/2018-04-16-winning-minesweeper/minesweeper.png"}}){: margin: 0 auto; display: block; }
{: refdef}

Great, so to accomplish this, there are various options. I'll be describing 3 approaches which can be used, namely

1. [Dynamic Instrumentation (using Frida or Cycript)](#dynamic-instrumentation)

2. [Writing a Theos tweak](#theos-tweak)

3. [dylib injection (will also work on non-jailbroken devices!)](#dylib-injection)

### Dynamic Instrumentation

In this post, I'll be using Frida to accomplish this task. To highlight the cells containing bombs, we first need to get a handle to the active `MinesweeperViewController` instance. This can be achieved by getting the `rootViewController` which happens to be the active instance of `MinesweeperViewController`. The following snippet demonstrates how this can be carried out with Frida.

{% highlight javascript %}
var UIApp = ObjC.classes.UIApplication;
var ui = UIApp.alloc();

mvc = ui.keyWindow().rootViewController();
{% endhighlight %}


The `MinesweeperViewController` has multiple members associated with it including `minecount`, `board`, `flagcount`, `zoomscale` and many more. The `board` function is useful to us because it returns the `BoardView` associated with the `MinesweeperViewController` instance, essentialy giving us access to to the game grid.

{% highlight c %}
BoardView *__cdecl -[MinesweeperViewController board](MinesweeperViewController *self, SEL a2)
{
  return self->board;
}
{% endhighlight %}

{% highlight shell_session %}
(ios) jai@Acheron ~ $ frida -U -n MinesweeperClassic2
     ____
    / _  |   Frida 10.7.7 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

...

[iPhone::MinesweeperClassic2]-> board = mvc.board();
{
    "handle": "0x10209f800"
}
[iPhone::MinesweeperClassic2]-> mvc.minecount()
10
[iPhone::MinesweeperClassic2]-> mvc.valueForKey_("flagcount").toString()
"0"
{% endhighlight %}

Now, all we have to do is iterate over the game grid and highlight all cells with value 17. To retrieve the value of a cell, the `-[BoardView gridAtx: y: ]` can be used which returns the value of the cell present at index (x,y).

{% highlight c %}
int __cdecl -[BoardView gridAtx:y:](BoardView *self, SEL a2, int x, int y)
{
  int v5; // [xsp+1Ch] [xbp-4h]

  if ( x & 0x80000000 || y & 0x80000000 || x >= self->width || y >= self->height )
    v5 = -1;
  else
    v5 = self->grid[x][y];
  return v5;
}
{% endhighlight %}

{% highlight shell_session %}
[iPhone::MinesweeperClassic2]-> board.gridAtx_y_(0,0)
16
[iPhone::MinesweeperClassic2]-> board.gridAtx_y_(0,1)
16
[iPhone::MinesweeperClassic2]-> board.gridAtx_y_(1,5)
17
{% endhighlight %}

Now we have all the primitives for sucessfully marking the bombs. One caveat about using the `-[Board setGrid: x: y;]` function is that, since this function is changing the UI of the application, to reflect all changes without any delay, we have to call this function from the main thread. This can be done by scheduling the function with GCD (Grand Central Dispatch).

{% highlight javascript %}
ObjC.schedule(ObjC.mainQueue, function () {
    board.setGrid_x_y_(0xd, x, y);
});
{% endhighlight %}

This sums up the steps. The complete Frida script:

{% highlight javascript %}
var mvc = 0;
var board = 0;

// get top ViewController which is MinesweeperViewController
// get BoardView of MinesweeperViewController
function init() {
    var UIApp = ObjC.classes.UIApplication;
    var ui = UIApp.alloc();

    mvc = ui.keyWindow().rootViewController();
    board = mvc.board();
}

// mark bombs on the grid using setGrid method of BoardView
// UI changes must be done in the main thread to update automatically
// therefore use GCD
function mark(x, y) {
    ObjC.schedule(ObjC.mainQueue, function () {
        board.setGrid_x_y_(0xd, x, y);
    });
}

// function to find bombs from the grid
// all cells with value 17 are bombs
// if you press a bomb on the first try, then bombs will
// be re-shuffled
function findBombs() {
    var x = parseInt(board.valueForKey_("width").toString());
    var y = parseInt(board.valueForKey_("height").toString());

    for (var i = 0; i < x; i++)
        for (var j = 0; j < y; j++)
            if (board.gridAtx_y_(i, j) == 17)
                mark(i, j);
}

init();
findBombs();
{% endhighlight %}

And here it is in action.

{% highlight shell_session %}
frida -U -l bomb.js -n MinesweeperClassic2
{% endhighlight %}

{:refdef: style="text-align: center;"}
![Flags]({{"/assets/2018-04-16-winning-minesweeper/flags_1.png"}}) ![Win]({{"/assets/2018-04-16-winning-minesweeper/win_1.png"}})
{: refdef}

One further optional improvement can be made here. Instead of calling our function `init` and `findBombs` manually from the script, we can replace the implementation of a built-in function of the app. A viable candidate for this is the `-[MinesweeperViewController toggleFlag]` function which is called when the `Flag` button present in the upper right corner of the game is pressed. This method of switching or replacing function implementations is called method swizzling.

I'd like to digress a little over here and mention a small note about method swizzling.

```
                                 +----------+
                                 | Class A  |
                                 +----------+
               +---------+                        +---------+
               |SELECTOR |                        |SELECTOR |
               |-s1      |                        |-s2      |
               +---------+                        +---------+
                   +                                  +
                   |                                  |
                   v                                  v
               +---------------+                  +---------------+
               |IMPLEMENTATION |                  |IMPLEMENTATION |
               |    -s1        |                  |   -s2         |
               +---------------+                  +---------------+
```

Each method has a selector and a corresponding implementation. Method swizzling switches or replaces the implementation. For example, we can switch the implementation of s1 and s2 like so.

```
                                 +----------+
                                 | Class A  |
                                 +----------+
               +---------+                        +---------+
               |SELECTOR |                        |SELECTOR |
               |-s1      |                        |-s2      |
               +---------+                        +---------+
                   +                                  +
                   |                                  |
                   v                                  v
               +---------------+                  +---------------+
               |IMPLEMENTATION |                  |IMPLEMENTATION |
               |    -s2        |                  |   -s1         |
               +---------------+                  +---------------+
```

So now, when the selector `s1` of `class A` is used on an instance of `A`, the implementation corresponds to `s2` and vice-versa. This is possible because the Objective-C runtime supports dispatching methods at runtime and provides APIs to get and set the method implementations.

There are many detailed articles about method swizzling on the internet if you would like to read about it in detail.

Coming back to our addition, we can change the implementation of `-[MinesweeperViewController toggleFlag]` using Frida like so.

{% highlight javascript %}
// changes implementation of -[MinesweeperViewController toggleFlag:]
function changeImpl() {
    var MinesweeperViewController = ObjC.classes.MinesweeperViewController;
    var toggleFlag = MinesweeperViewController['- toggleFlag:'];
    toggleFlag.implementation = ObjC.implement(toggleFlag, function (handle, selector) {
        init();
        findBombs();
    });
}
{% endhighlight %}

This concludes our first technique. Now we'll look at another implementation of the same hack using a Theos tweak.

### Theos Tweak

This technique will only work on Jailbroken devices. This technique achieves code injection by leveraging the powerful [Cydia Substrate](http://www.cydiasubstrate.com) platform. Tweaks can be written in Logos which is a simplified version of Objective-C.

For this approch, we will replace `-[MinesweeperViewController toggleFlag]`'s implementation with our code to iterate over the game grid and populate all bomb cells with flags.

Since we are hooking a custom ViewController which is not available by default, we will have to make a header file for our tweak so that it won't complain about the functions we will use.

{% highlight objective_c %}
@interface BoardView : NSObject
- (int) gridAtx:(int)arg1 y:(int)arg2;
- (void) setGrid:(int)arg1 x:(int)arg2 y:(int)arg3;
@end

@interface MinesweeperViewController
- (BoardView *)board;
@end
{% endhighlight %}

The tweak code is fairly simple and achieves the same purpose as the previous method.

{% highlight objective_c %}
#include "Mine.h"

%hook MinesweeperViewController

- (void)toggleFlag:(id)argument {
	BoardView *board = [self board];
	int x = [[board valueForKey: @"width"] intValue];
	int y = [[board valueForKey: @"height"] intValue];

	for (int i = 0; i < x; i++) {
		for (int j = 0; j < y; j++) {
			if ([board gridAtx: i y: j] == 17) {
				[board setGrid: 11 x: i y: j];
			}
		}
	}
}

%end
{% endhighlight %}

Behind the scenes, hooking is carried out using the `MSHookMessageEx` API provided by Cydia Substrate. This is basically a high-level wrapper for performing method swizzling.

Some of the requisites for building the tweak using Theos include specifying the bundle identifier of the app which in our case is `com.libertyforone.minesweeperclassic2`.

{% highlight shell_session %}
(ios) jai@Acheron ~/Documents/tmp/minesweeper/tweak/minefinder $ export THEOS=~/theos
(ios) jai@Acheron ~/Documents/tmp/minesweeper/tweak/minefinder $ export THEOS_DEVICE_IP=127.0.0.1
(ios) jai@Acheron ~/Documents/tmp/minesweeper/tweak/minefinder $ export THEOS_DEVICE_PORT=2222
(ios) jai@Acheron ~/Documents/tmp/minesweeper/tweak/minefinder $ make package install
> Making all for tweak minefinder…
==> Preprocessing Tweak.xm…
==> Compiling Tweak.xm (armv7)…
==> Linking tweak minefinder (armv7)…
clang: warning: libstdc++ is deprecated; move to libc++ with a minimum deployment target of iOS 7 [-Wdeprecated]
==> Generating debug symbols for minefinder (armv7)…
==> Preprocessing Tweak.xm…
==> Compiling Tweak.xm (arm64)…
==> Linking tweak minefinder (arm64)…
clang: warning: libstdc++ is deprecated; move to libc++ with a minimum deployment target of iOS 7 [-Wdeprecated]
==> Generating debug symbols for minefinder (arm64)…
==> Merging tweak minefinder…
==> Signing minefinder…
> Making stage for tweak minefinder…
dm.pl: building package `com.jaiverma.minefinder:iphoneos-arm' in `./packages/com.jaiverma.minefinder_0.0.1-5+debug_iphoneos-arm.deb'
==> Installing…
root@127.0.0.1's password:
Selecting previously unselected package com.jaiverma.minefinder.
(Reading database ... 1592 files and directories currently installed.)
Preparing to unpack /tmp/_theos_install.deb ...
Unpacking com.jaiverma.minefinder (0.0.1-5+debug) ...
Setting up com.jaiverma.minefinder (0.0.1-5+debug) ...
{% endhighlight %}

Once the tweak has been built and deployed to the iPhone, we can view it and Cydia and see that it works as expected.

{:refdef: style="text-align: center;"}
![Tweak]({{"/assets/2018-04-16-winning-minesweeper/cydia.png"}}) ![Win]({{"/assets/2018-04-16-winning-minesweeper/win_2.png"}})
{: refdef}

This concludes the second technique and now we'll finally look at a way how all this can be accomplished for a non-jailbroken device.

### dylib Injection
This technique works for jailed devices but requires modifying the binary. In this technique, we will make a Cocoa Touch Framework which will be used to perform method swizzling similar to the last technique but using Apple's API.

If we were performing method swizzling on a method present in one of Apple's standard libraries such as UIKit, CoreFoundation, CoreLocation, etc. we could have simply achieved this by writing a `Category` which simply put is, a way of extending a class' functionality and is a standard way to perform method swizzling. Unfortunately in our case, we need to swizzle a method present in non-standard custom class, namely `MinesweeperViewController`.

We will have to use Apple's [Objective-C Runtime API](https://developer.apple.com/documentation/objectivec/objective_c_runtime) for achieving our goal.

First we will create a custom class with our implementation which will replace `toggleFlag`. The header file looks like:

{% highlight objective_c %}
...

@interface BoardView : UIView
- (int) gridAtx:(int)arg1 y:(int)arg2;
- (void) setGrid:(int)arg1 x:(int)arg2 y:(int)arg3;
@end

@interface CustomClass : UIViewController
- (BoardView *) board;
+ (void) sayHello;
@end
{% endhighlight %}

The corresponding implementation is:

{% highlight objective_c %}
@implementation CustomClass

- (void)toggleFlag:(id)argument {
    BoardView *board = [self board];
    
    int x = [[board valueForKey: @"width"] intValue];
    int y = [[board valueForKey: @"height"] intValue];
    
    for (int i = 0; i < x; i++) {
        for (int j = 0; j < y; j++) {
            if ([board gridAtx: i y: j] == 17) {
                [board setGrid: 11 x: i y: j];
            }
        }
    }
}

@end
{% endhighlight %}

This functionality is identical to the previous examples. Now that we have this out of the way, we will perform method swizzling by finding our class `MinesweeperViewController`, in memory and replacing `-[MinesweeperViewController toggleFlag]`'s implementation with our implementation.

According to Apple's documentation, `func objc_getClass(_ name: UnsafePointer<Int8>) -> Any!` takes the name of the class to look up and returns the Class object for the named class, or `nil` if the class is not registered with the Objective-C runtime.

`func class_getInstanceMethod(_ cls: AnyClass?, _ name: Selector) -> Method?` returns the method that corresponds to the implementation of the selector specified by `aSelector` for the class specified by `aClass`, or `NULL` if the specified class or its superclasses do not contain an instance method with the specified selector.

`func method_exchangeImplementations(_ m1: Method, _ m2: Method)` exchanges the implementation of two methods.

In our scenario, these are all the function's we require for method swizzling.

The following code snippet is responsible for replacing the implementation of `-[MinesweeperViewController toggleFlag]` with our implementation `-[CustomClass toggleFlag]`.

{% highlight objective_c %}
@implementation loader
static void __attribute__((constructor)) init(void) {
    id MinesweeperViewController = objc_getClass("MinesweeperViewController");
    SEL toggle = NSSelectorFromString(@"toggleFlag:");
    
    
    Method original = class_getInstanceMethod(MinesweeperViewController, toggle);
    Method replacement = class_getInstanceMethod([CustomClass self], toggle);
    
    method_exchangeImplementations(original, replacement);
}
@end
{% endhighlight %}

Since we've used `static void __attribute__((constructor))` modifier for the `init` function, this will be called when the `loader` class is loaded in memory which is a suitable entry-point for code injection.

Once the framework has been built using Xcode, we can get the generated dylib from the built Framework and package it with our app.

{% highlight shell_session %}
jai@Acheron ~/Documents/tmp/minesweeper/ipa $ unzip com.libertyforone.minesweeperclassic2-iOS9.0-\(Clutch-2.0.4\ DEBUG\).ipa
Archive:  com.libertyforone.minesweeperclassic2-iOS9.0-(Clutch-2.0.4 DEBUG).ipa
  inflating: iTunesArtwork
  inflating: Payload/MinesweeperClassic2.app/512x512-logo.png
  ...
{% endhighlight %}

We'll unzip the decrypted ipa which be obtained via Clutch detailed in the first method, and copy over our dylib into a new folder inside the Payload folder of the app. Now for instructing the application to load our dylib, we have to modify the app binary. iOS binaries are of the Mach-O file format and we'll be modifying the load commands section using a tool called [optool](https://github.com/alexzielenski/optool).

{% highlight shell_session %}
jai@Acheron ~/Documents/tmp/optool/bin (master*) $ ./optool install -c load -p "@executable_path/dylib/Swizzle" -t "/Users/jai/Documents/tmp/minesweeper/ipa/Payload/MinesweeperClassic2.app/MinesweeperClassic2"
Found thin header...
Inserting a LC_LOAD_DYLIB command for architecture: arm64
Successfully inserted a LC_LOAD_DYLIB command for arm64
Writing executable to /Users/jai/Documents/tmp/minesweeper/ipa/Payload/MinesweeperClassic2.app/MinesweeperClassic2...
{% endhighlight %}

This inserts an LC_LOAD_DYLIB command into the load section of the binary and increments the Mach header's `ncmds` variable.

Now we can repackage and sign the `ipa` using a Developer Profile and install the `ipa` onto a device using Cydia Impactor.

Note that these techniques work for all difficulty levels in the game and for any number of mines!

{:refdef: style="text-align: center;"}
![Win Easy]({{"/assets/2018-04-16-winning-minesweeper/win_4.png"}}) ![Win Medium]({{"/assets/2018-04-16-winning-minesweeper/win_3.png"}})
{: refdef}

Well this finally concludes this post. I hope you enjoyed reading it and learned something new. Feel free to leave comments for questions or any corrections!
