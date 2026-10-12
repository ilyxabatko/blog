+++
date = '2026-10-11'
draft = false
title = 'Chiffre Unique'
tags = ["reverse-engineering", "ghidra", "linux", "c++"]
summary = "Reversing an ELF binary with Ghidra & solving a sudoku board to capture the flag."
+++

## CTF Overview

This time I solved a CTF challenge from [Hackropole](https://hackropole.fr/en/) called `Chiffre Unique`, which required me to identify Sudoku patterns and solve an actual board that was stored in the binary. The flag turned out to be a `SHA256` hash, so there was no shortcut this time to obtain the flag.

## Setup and Workflow

1. As I got more familiar with the `ELF` binaries reversing, I started with a small recon to see what I'm about to work with by running `file`, `ltrace`, `strace`, `strings`. There was nothing special during this phase, but with the `strings` command I found out that some hashing is used in the binary:

```
SHA256_Init
SHA256_Final
SHA256_Update
```

2. Then it came to a Ghidra analysis, looking for the main function, identifying Sudoku board checks and solving it, so this time I could apply my programming skills to get the flag.

## Solving Process

1. Following the `main` function from the entrypoint, I noticed, first of all, a loop that processes input and fills up a `16x16` table, then does some checks on the table, and calls the `print_flag` function that has some `SHA256` stuff inside. Here's the `main` function with some renaming done:


```c
undefined8 main(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined8 status;
  long col;
  char *resultStr;
  byte (*row) [16];
  int counter;
  uint inputBuff;
  byte table [16] [16];

  counter = 0;
  row = table;
  do {
    col = 0;
    do {
      __isoc99_scanf(&DAT_00102011,&inputBuff);
      if (0xf < inputBuff) {
        resultStr = "Invalid argument.";
        goto EXIT;
      }
      (*row)[col] = (byte)inputBuff;
      col = col + 1;
    } while (col != 16);
    counter = counter + 16;
    row = row + 1;
  } while (counter != 256);
  uVar1 = check_rows(table);
  uVar2 = check_cols(table);
  uVar3 = check_boxes(table);
  uVar4 = check_clues();
  if ((uVar4 & uVar1 & uVar2 & uVar3) == 0) {
    resultStr = "Input incorrect.";
EXIT:
    puts(resultStr);
    status = 1;
  }
  else {
    puts("Congratulations ! ");
    print_flag(table);
    status = 0;
  }
  return status;
}
```

2. In the `scanf` function arguments I found a reference to the format specifier:

```c
__isoc99_scanf(&DAT_00102011,&inputBuff);
```

```
DAT_00102011
25              ??         25h    %
78              ??         78h    x
00              ??         00h
```

which means that the input is processed as hexadecimal integers.

3. The loop fills rows one by one with the numbers between 0 to 15. At this point I already made an assumption that I have some kind of a sudoku board setup.

4. The first checker function is basically a sudoku row checker for our table:

```c
bool check_rows(long table)
{
  long counter;
  int distinct_total;
  char seen [24];
  char *pointer;
  long tableEnd;

  tableEnd = table + 256;
  distinct_total = 0;
  do {
    counter = 0;
    seen[0] = '\0';
    seen[1] = '\0';
    seen[2] = '\0';
    seen[3] = '\0';
    seen[4] = '\0';
    seen[5] = '\0';
    seen[6] = '\0';
    seen[7] = '\0';
    seen[8] = '\0';
    seen[9] = '\0';
    seen[10] = '\0';
    seen[0xb] = '\0';
    seen[0xc] = '\0';
    seen[0xd] = '\0';
    seen[0xe] = '\0';
    seen[0xf] = '\0';

    do {
      pointer = (char *)(table + counter);
      counter = counter + 1;
      seen[*pointer] = '\x01';
    } while (counter != 16);

    counter = 0;
    do {
      pointer = seen + counter;
      counter = counter + 1;
      distinct_total = distinct_total + *pointer;
    } while (counter != 16);

    table = table + 16;
  } while (tableEnd != table);

  return distinct_total == 256;
}
```

The idea of the function appeared to be very simple: make sure that every number from 0 to 15 is distinct in each row.

5. The next checker function is also simple, one could guess what it does without even looking at it. Right, it's a sudoku column checker:

```c
byte check_cols(char *table)
{
  byte status;
  char *cell;
  byte available [16];
  char *columnEnd;
  char digit;

  columnEnd = table + 16;
  status = 1;
  do {
    available[0] = 1;
    available[1] = 1;
    available[2] = 1;
    available[3] = 1;
    available[4] = 1;
    available[5] = 1;
    available[6] = 1;
    available[7] = 1;
    available[8] = 1;
    available[9] = 1;
    available[10] = 1;
    available[0xb] = 1;
    available[0xc] = 1;
    available[0xd] = 1;
    available[0xe] = 1;
    available[0xf] = 1;
    cell = table;

    do {
      digit = *cell;
      cell = cell + 16;
      status = status & available[digit];
      available[digit] = 0;
    } while (cell != table + 256);

    table = table + 1;
  } while (table != columnEnd);

  return status;
}
```

The approach here is a bit different from the row checker function. It disables an `available` bit after a number was seen, and if the same number appears again, the `status = status & available[digit]` bitwise operation will make sure the function returns `false` and we're cooked.

6. The third checker function is known, it checks 4x4 boxes, but the decompiled function is very hard to read as it contains a lot of bit manipulations even after some renaming:

```c
byte check_boxes(long table)
{
  byte status;
  uint idx;
  uint uVar1;
  uint boxRow;
  int boxCol;
  uint j;

  boxRow = 0;
  status = 1;
  do {
    boxCol = (boxRow & 3) * 4;
    idx = 0;
    do {
      uVar1 = idx + 1;
      for (j = uVar1; j != 16; j = j + 1) {
        status = status & *(char *)(table + (int)((((int)j >> 2) + (boxRow & 0xfffffffc)) * 16 +
                                                 (j & 3) + boxCol)) !=
                          *(char *)(table + (int)((((int)idx >> 2) + (boxRow & 0xfffffffc)) * 16 +
                                                 (idx & 3) + boxCol));
      }
      idx = uVar1;
    } while (uVar1 != 16);

    boxRow = boxRow + 1;
  } while (boxRow != 16);

  return status;
}
```

Here's what the function does:
    - First, a starting point of a box is found:
    ```c
    boxRow = (6 / 4) * 4 // = 4
    boxCol = (6 % 4) * 4 // = 8
    ```
    So the starting point is `table[4][8]` and it covers rows 4-7 and columns 8-11

    - To index through the cells in the box, the following formula is used here: `cell[i] = table[boxRow + i / 4][boxCol + i % 4]`.

    - Then a set of comparisons between pairs happen. First, cell `0` is compared with every next cell, then cell `1` is compared with all the next ones. This way, we avoid comparing pairs that we already checked, but it still takes 120 comparisons in total per box.

    - `status` is compared like this: `status = status & (cell[i] != cell[j])`, making sure that the check fails in case a pair of cells contain the same number.

7. Now the last sudoku setup step: check the solution against clues that the author prepared, otherwise any 16x16 sudoku solution would work:

```c
byte check_clues(long table)
{
  byte status;
  long counter;
  char *clue;
  char *num;

  counter = 0;
  status = 1;

  do {
    clue = &g_Puzzle + counter;
    num = (char *)(table + counter);
    counter = counter + 1;
    status = status & (*num == *clue || *clue == -1);
  } while (counter != 256);

  return status;
}
```

There's a global variable that points to a 256 bytes data spot, where every byte is either a number I have to put in my sudoku at a certain position, or the `0xff` byte that means `empty cell` and should be filled in.

8. I copied those 256 bytes from Ghidra by selecting them -> `Copy Special` -> `C array` and got an array of hex bytes. I decided to write a sudoku solver in `C++`.

9. First I've written a straightforward solution - recursion: find an empty cell, fill it with a number that is available for that row, col and box, then solve recursively for the next cells, and backtrack if I hit a dead end. But this approach resulted in a huge options tree and I stopped it after about 30 seconds to figure our a better solution.

I changed the code a bit to solve it like a human would - find the empty cell which has the least amount of options (ideally 1 or 2) and start solving from it. That way I'm less likely to hit a dead end further as the options tree doesn't grow much. In addition, it reduces the options of its neighbors, reducing the solution time drastically. Now it runs in under 1 second.

I'll show the `solve()` function only to give you an idea of how I implemented it:

```cpp
bool solve() {
  int bestRow = -1;
  int bestCol = -1;
  int bestCount = 17;

  // pick the empty cell with the fewest valid digits
  for (int row = 0; row < 16; row++)
    for (int col = 0; col < 16; col++)
      if (grid[row][col] == EMPTY) {
        int count = count_options(row, col); // counts the cell options (the fewer the better)

        if (count < bestCount) {
          bestCount = count;
          bestRow = row;
          bestCol = col;
        }
      }

  if (bestRow == -1) {
    return true; // no empty cells left, the puzzle is solved, return
  }

  if (bestCount == 0) {
    return false; // some cell has no valid digit, it's a dead end, return
  }

  for (int i = 0; i < 16; i++) {
    // checks if a digit can be placed, this is the
    // reversed version of checks from binary pretty much
    if (!can_place(bestRow, bestCol, i)) {
        continue;
    }

    grid[bestRow][bestCol] = i;
    if (solve()) {
      return true;
    }

    grid[bestRow][bestCol] = EMPTY;
  }

  return false;
}
```

10. Now as I have the sudoku board solved, it's time to obtain the flag. Here's the function that prints it:

```c
void print_flag(void *param_1)
{
  byte *pbVar1;
  long lVar2;
  byte local_a8 [32];
  SHA256_CTX local_88;

  lVar2 = 0;
  SHA256_Init(&local_88);
  SHA256_Update(&local_88,param_1,0x100);
  SHA256_Final(local_a8,&local_88);
  printf("FCSC{");
  do {
    pbVar1 = local_a8 + lVar2;
    lVar2 = lVar2 + 1;
    printf("%02x",(ulong)*pbVar1);
  } while (lVar2 != 0x20);
  puts("}");
  return;
}
```

This function has the standard `OpenSSL` three step SHA256 hashing API that comes from dynamically linked `libcrypto` library:
1. Init - sets up the context;
2. Update - feeds in the data (my solved sudoku board in this case);
3. Final - produces a digest (hash);

This approach is interesting as it eliminates any shortcut to capture the flag with, say, binary patching or strings lookup, and requires a board solution to produce the correct `SHA256` 32 bytes hash from my data.

Time to feed the output of the solver to the chiffre binary and capture the flag (keeping the full solution hidden):

```
[elijah@elijah-arch Downloads]$ ~/Desktop/sudoku-solver/./solver
f 0 1 3 9 d 4 5 7 a b 2 8 6 c e
5 7 d 8 a 6 c b 9 4 f e 2 3 1 0
2 4 6 c 3 8 f e 5 d 0 1 9 b a 7
...............................
b 6 c 4 8 9 7 d 0 3 a f e 5 2 1
1 f 0 5 e c b 4 2 8 7 9 d a 6 3
[elijah@elijah-arch Downloads]$ ~/Desktop/sudoku-solver/./solver | ./chiffre-unique
Congratulations !
FCSC{00119cf9663f................cf66af54c53e6}
```

## What I Learned

### Bitwise Operations Recalling

With the `check_boxes` function I recalled and learned some bitwise patterns:

> 1. `x & 3` means `x % 4`, it keeps the lowest 2 bits as the remainder;
> 2. `x >> 2` means dividing by 4 (in this case), so `x >> y` == `x / 2^y`
> 3. `x & 0xfffffffc` means `(x / 4) * 4` - 2 lowest bits cleared (`x & 0x..100`), hence rounded to a multiple of 4.

## Conclusion

This time it was mostly about reading decompiled C code and writing a Sudoku board solution, hence I could get some rust off and write a bit of C++. Soon, I'll start writing a project in C++ that is about reversing and anti-cheat in games, hence I'll be writing a `devlog` and sharing my progress here.

Onto the next one!

