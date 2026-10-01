+++
date = '2026-10-01'
draft = false
title = 'Catch Me If You Can'
tags = ["reverse-engineering", "ghidra", "windows"]
summary = "Reversing my first Windows PE with Ghidra & patching assembly instruction to capture the flag."
+++

## CTF Overview

Here's another CTF challenge from [Hackropole](https://hackropole.fr/en/) called `Catch me if you can` where you have to catch DiCaprio icon in order to get the flag. But whenever you try to hover over the icon, it changes its place. Keyboard input is disabled (you'll find out why later) in case you'd think about using `TAB` key to enumerate over the cells.
!["Catch Me" game window](/images/catchme/catchme-game.png)

> Note: every function snippet has important variables renamed by me during the reversing process to make the examples clear.

## Setup and Workflow

This is the first time I'm reversing a Windows PE format, hence I decided to continue using Ghidra to get more practice with this tool. I also had to use a bit of `x32dbg` and `PE Bear` tools, you'll see why later.

1. Before inspecting the executable in Ghidra, I ran the app in a VM and tried to catch DiCaprio with my bare hands and mouse, I couldnt...
2. Imported the file into Ghidra, faced the `entry` function with some boilerplate and the `main` function pointer:
```c
void entry(void)
{
  HMODULE hInstance;
  WPARAM uExitCode;
  _STARTUPINFOA local_50;
  
  GetStartupInfoA(&local_50);
  GetCommandLineA();
  hInstance = GetModuleHandleA((LPCSTR)0x0);
  uExitCode = main(hInstance);
                    /* WARNING: Subroutine does not return */
  ExitProcess(uExitCode);
}
```
3. Went through the `main` function and looked up the `Win32` API function I encountered.
4. Had to dig deeper and deeper into hooks procedures until I found the function that builds the flag.
5. Patched a couple of assembly instructions with Ghidra to avoid flag corruptions.
6. Ran the patched executable and got the flag!

## What I Learned

### Pseudo Random Mersenne Twister seeding

The first function I had to spend some time on was a pseudo random number generator, its seeding part to be precise that sets up an array of 624 32bit numbers, where the first element is the seed (`GetTickCount() output`):

```c
void __cdecl prng_seed(int *prngState,int ticksCount)
{
  int *piVar1;
  int *piVar2;
  
  if (ticksCount == 0) {
    ticksCount = -1;
  }

  *prngState = ticksCount;
  piVar1 = prngState + 1;

  do {
    ticksCount = ticksCount * 6069;
    piVar2 = piVar1 + 1;
    *piVar1 = ticksCount;
    piVar1 = piVar2;
  } while (prngState + 624 != piVar2);

  prngState[624] = 624;
  return;
}
```

It was hard to notice the pattern initially with the compiler optimizations. In the end, it's a simple loop where every next value is the previous value multiplied by `6069` in our case until we reach the last element (624). The approach is called `Mersenne Twister seeding`.

### Keyboard Input Disallowing

The author disallows keyboard actions (e.g. pressing `TAB` to move between cells) with this interesting condition form that the compiler made:
```c
if (9 < message.message + -WM_KEYDOWN) {...}
```

1. `WM_KEYDOWN` - `0x100` keyboard event, and `0x109` - `WM_UNICHAR` - a range of keyboard events;
2. if message is lower than `0x100`, the result is negative, but the `message` is of type `UINT`, so `message - 0x100` wraps around - true, process;
3. if message is bigger than `0x109` - true, process
4. for keyboard events, it stays in the range `0..9`, so the if's body is skipped

If the message is not a keyboard one, it's translated and dispatched for further steps.

### Mouse Hook Procedure

I got familiar with the way Win32 API enables callbacks for mouse events:
`g_mouseHook = SetWindowsHookExA(WH_MOUSE,processMouseEvent,(HINSTANCE)0x0,n);`

The function we pass as a procedure is to be called on every mouse event:

```c
void processMouseEvent(int code,WPARAM mouseEvent,LPARAM pMouseInfo)
{
  bool iconHovered;
  undefined3 extraout_var;
  
  if ((-1 < code) && (mouseEvent == WM_MOUSEMOVE)) {
    iconHovered = isIconHovered();
    if (CONCAT31(extraout_var,iconHovered) != 0) {
      setNewCellTarget();
    }
  }
  CallNextHookEx(g_mouseHook,code,mouseEvent,pMouseInfo);
  return;
}
```

The idea is simple - if the event is `WM_MOUSEMOVE` and the icon is hovered, then we move DiCaprio's position.

### How To Process Big Functions

The `setNewCellTarget()`function is called once the icon is hovered (just look through it briefly):

```c
void setNewCellTarget(void)
{
  uint num;
  HWND cell;
  int iVar1;
  tagPOINT cursorPos;
  tagPOINT local_24 [2];
  int cellId;
  
  cell = GetDlgItem(DAT_0047c00c,g_targetId);
  SendMessageA(cell,0xf7,0,0);
  GetCursorPos(&cursorPos);
  do {
    do {
      num = prng_next((uint *)&g_prngState);
      cellId = num % 0x46 + 100;
      cell = GetDlgItem(DAT_0047c00c,cellId);
      local_24[0].y = cursorPos.y;
      local_24[0].x = cursorPos.x;
      ScreenToClient(cell,local_24);
      local_24[0].x = local_24[0].x - _DAT_0047a020;
      local_24[0].y = local_24[0].y - DAT_0047a024;
    } while (g_targetId == cellId);
    iVar1 = local_24[0].x;
    if (-1 < -local_24[0].x) {
      iVar1 = -local_24[0].x;
    }
    if (DAT_0047a028 <= iVar1) break;
    iVar1 = -local_24[0].y;
    if (-local_24[0].y < 0) {
      iVar1 = local_24[0].y;
    }
  } while (iVar1 < DAT_0047a02c);
  SendMessageA(cell,0xf7,0,g_hIcon);
  g_targetId = cellId;
  return;
}
```

It was a big function to read and digest, especially before some renamings, it scared me initially, hence I had to learn an approach:

> You should never try to read and understand every letter of a disassembled function. Here're the steps I took and how I applied it:
> 1. Read the API calls that give an overall idea of what happens in the function: e.g. `SendMessageA` - `0xf7` as the 2nd argument means `BM_SETIMAGE`, and the 4th `0` `lParam` means `no image`. We clear a cell basically.
> 2. Find a state change, in our case it changes global `DAT_0047c000 = cellId;` state, so we can assume it sets a new target cell for the icon.
> 3. Collapse the parts of the code (mentally or phisically) that we already saw and understood OR that might seem like visual clutter. You can always come back to it if needed.
> 4. Focus on the main logic after all of the steps above are applied.

Here's what I ended up with that approach:

```c
void setNewCellTarget(void)
{
  SendMessageA(cell,0xf7,0,0);  // clear a cell
  do {
    num = prng_next((uint *)&g_prngState);  // get a pseudo random num
    cellId = num % 0x46 + 100;    // new cell id is in range 100..169 (70 cells total)
  } while (g_targetId == cellId || cursorIsNear());

  SendMessageA(cell,0xf7,0,g_hIcon);    // move the icon to a new cell
  g_targetId = cellId;    // update the target cell state
  return;
}
```

It gives me enough context to understand what it does - it allows `DiCaprio` to run away from my mouse pointer once I hover over the icon. That's it, I can move on.

## Solution

As I continued, I noticed a Dialog box procedure function:
`CreateDialogParamA(hInstance,(LPCSTR)100,(HWND)0x0,processDialogMsg,0);`

It's a big function that sets up the dialog window on the `WM_INITDIALOG` message first, but I highlighted the part that I found interesting on the way towards the solution:

```c
bool processDialogMsg(HWND hDialogBox,uint uMsg,uint cellId)
{
   if (WM_INITDIALOG < uMsg) {
    if (uMsg != 0x111) {
      return false;
    }

    bVar1 = isIconHovered();
    if (CONCAT31(extraout_var,bVar1) != 0) {
      setNewCellTarget();
    }

    if (99 < cellId) {
      pHVar2 = GetModuleHandleA((LPCSTR)0x0);
      iVar3 = LoadStringA(pHVar2,200,string_buffer,0x100);
      if (iVar3 == 0) {
        return false;
      }
      bVar1 = buildResult(cellId,result_string);

      if (CONCAT31(extraout_var_00,bVar1) != 0) {
        pHVar2 = GetModuleHandleA((LPCSTR)0x0);
        iVar3 = LoadStringA(pHVar2,0xc9,result_string,0x27);

        if (iVar3 == 0) {
          return false;
        }
      }

      MessageBoxA(hDialogBox,result_string,string_buffer,0);
    }
    DestroyWindow(hDialogBox);
    return true;
  }

  PostQuitMessage(0);
  return true;
}
```

1. First, it checks if the message is `WM_COMMAND` (`0x111`) that is called once a user interacts with a control (e.g. clicks a button).
2. It sets a new target cell if a user hovers over the target.
3. If the `cellId` a user interacted with is in the range (remember, cell IDs are in range `100 .. 169`), then we enter the part that sets up a game's result: a message box and its content. The content depends on if the `buildResult` returns true or false. If it's false, then the game reuslt string is set to the `Gone!` value from `0xc9` address, which means the game is over.

The `buildResult` function does a set of transformations and it'd be tough to figure out the flag statically, but at least I know it should give me a flag: `wsprintfA(resultString,"FCSC{%.32s}",local_3c);`

The **main problem** is that if we click an empty cell, we got the flag `XOR`ed and the decrypted bytes are encrypted again. 

### Initial (failed) idea

My initial idea was to replace `cellId` I pass to this function with the `g_targetId` to avoid XOR blocks by updating assembly:

```asm
; from this
MOV     EAX,dword ptr [ESP + cellId]

; to this
MOV     EAX,dword ptr [g_targetId]
```

First issue was the `ASLR (Address Space Layout Randomization)` that changes the base address of my EXE on program restart - `x32dbg` showed it clearly in the `Symbols` tab. After turning off ASLR with the `PE Bear` tool, I still had an `ACCESS VIOLATION` error. Apparently, my patch didn't work as it was a shared jump target and affected a path I didn't notice.

### Actual Solution

Hence, I decided to simplify the approach and flip the comparisons of 3 instructions so that even with `g_targetId != cellId` XOR blocks are omitted. This way my patch affects the instructions that touches the corruption branches only:

```asm
; before
CMP        dword ptr [g_targetId],EAX
JZ         LAB_004010ff

; after
CMP        dword ptr [g_targetId],EAX
JMP        LAB_004010ff
```

Then I exported a patched executable from Ghidra, ran it, and DiCaprio was caught!
!["Catch Me" flag captured](/images/catchme/catchme-solution.png)
