#Challenge 8
####Binary: gdssagh
####Type: PE Executable
####Arch: x86
##Josh's Solution

When the binary is run it simply prints `the one who seeks finds...`. When we run strings on the binary, we can see base-64 encoded data.

```
iVBORw0KGgoAAAANSUhEUgAAAlgAAAHgCAIAAAD2dYQOAAEAAElEQVR4nIT9b5Ak13UfCp57
8ubNW7eysrOrq6trenp6GoPBcDAcjkCQhGCIhGmQomg/WfbKtGQ7HLbCsbGxX97au/Ei/OHt
ft5dvxfvbXgdu7L3xYsNr0PPT6a1WlpS6FESDfFBFAiCIDgYDgaNRqPR6Ompqa6uzs7Kunnz
5smT+6F6QNnWxubExHTU1J+u/HN+f87v3BT/h3/275xbWJdrHQwHcYu1tWfM1O+vMGM2W0Sy
U3kochqkAyn1xB3FsZGSAShJVBqbQEIAKKX03jMAAzGQ1hK19M6Wc5HnOTBrrR05u5h3E725
[snipped]
CiE8x3xrjYjJ6kNED0d0UhZARVoyBgQR4RFwh6abqhsyYOuCBB5UDWOsFESS8IIqppoOfnbT
ljYkuyMi9ZorXEZEIMCmCk0L0lqz1rJi7fAI5izeqT3ICYucOqxWkrd9qBlvdej3Pda+Rpiv
cjmTbpGMJdXIIyISAql5IDv7wJ1I9/7zcTH7/JU/fMcR6nsTQyt/2E322P/i/xepIVI4nOLY
RQAAAABJRU5ErkJggg==j
```

Base-64 decoding this data produces a valid .PNG file.

<img src="imgs/chal8-gdssagh.png" width="500"></br>

Using `zsteg` on the image reveals that it contains a PE executable.

```Bash
b1,rgb,msb,xy       .. file: PE32 executable Intel 80386 32-bit
    00000000: 4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
    00000010: b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
    00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    00000030: 00 00 00 00 00 00 00 00  00 00 00 00 b0 00 00 00  |................|
    00000040: 0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|
    00000050: 69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|
    00000060: 74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |
    00000070: 6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00  |mode....$.......|
    00000080: 5d 5c 6d c1 19 3d 03 92  19 3d 03 92 19 3d 03 92  |]\m..=...=...=..|
    00000090: 97 22 10 92 1e 3d 03 92  e5 1d 11 92 18 3d 03 92  |."...=.......=..|
    000000a0: 52 69 63 68 19 3d 03 92  00 00 00 00 00 00 00 00  |Rich.=..........|
    000000b0: 50 45 00 00 4c 01 03 00  e8 39 a1 55 00 00 00 00  |PE..L....9.U....|
    000000c0: 00 00 00 00 e0 00 0f 01  0b 01 05 0c 00 02 00 00  |................|
    000000d0: 00 04 00 00 00 00 00 00  00 10 00 00 00 10 00 00  |................|
    000000e0: 00 20 00 00 00 00 40 00  00 10 00 00 00 02 00 00  |. ....@.........|
    000000f0: 04 00 00 00 04 00 00 00  04                       |.........       |
```

From there, I simply extracted the hidden executable and ran `strings` on it to retrieve the email.

```Bash
jwang@avantgarde:~/Documents/flareon15$ zsteg gdssagh.png --extract b1,rgb,msb,xy  > gdssagh.exe
```

```Bash
jwang@avantgarde:~/Documents/flareon15$ strings gdssagh.exe
!This program cannot be run in DOS mode.
Rich
.text
é.rdata
@.data
ExitProcess
kernel32.dll
printf
msvcrt.dll
Im_in_ur_p1cs@flare-on.com
```
