#Challenge 1
####Binary: i_am_happy_you_are_to_playing_the_flareon_challenge
####Type: PE Executable
####Arch: x86

##Josh's Solution
The challenge starts off with level 1 which is fairly trivial. You are given an executable which prompts you for the correct password.
<br><img src="imgs/chal1-prompt.png" width="300"><br>
Looking at the disassembly, I found the program XOR's each character in the user input with 0x7D and compares the result to the elements in an array at address `0x402140`. If the result of XOR-ing each char in the user input matches all chars in the array, "You are success" is printed. 

<br><img src="imgs/chal1-ida-1.png" width="500"><br>
<br><img src="imgs/chal1-secret.png" width="300"><br>

To solve this challenge, just XOR every character in the array with 0x7D. This can be done very quickly in Python.

```bash
rh0gue@deception:~/spartansecurity/Writeups/flareon15$ python
Python 2.7.8 (default, Nov  7 2014, 23:35:36) 
[GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.54)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> x = [0x1f,0x08,0x13,0x13,0x4,0x22,0xe,0x11,0x4d,0xd,0x18,0x3d,0x1b,0x11,0x1c,0xf,0x18,0x50,0x12,0x13,0x53,0x1e,0x12,0x10]
>>> for y in x:
...     print chr(y^0x7d)
... 
b
u
n
n
y
_
s
l
0
p
e
@
f
l
a
r
e
-
o
n
.
c
o
m
``` 

