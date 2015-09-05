#Challenge 4
##Binary: youPecks
##Type: PE Executable
##Arch: x86_x64

##Armen's Solution
The first thing we see when throwing this binary into PEiD is that it is packed, apparently with UPX (although it is reportedly packed with Crypto-Lock v2.02, according to the pedump utility.)
<br><img src="imgs/chal4-Peid.jpg" width="500"></br>

Initially running the program yields the following output:
`2 + 2 = 4`

We unpack the program with the UPX utility using the following command:
`upx -d youPecks`

The program now reads nicely in a disassembler.  However, running the unpacked version yields new output.  The screenshot below shows each of the above steps:
<br><img src="imgs/chal4-RunAndUnpack.jpg" width="500"></br>

Clearly, unpacking the program using the UPX utility has changed the binary.

Continuing through to the disassembly of the unpacked version (for readability, but keeping in mind that the program has been transformed), we can see the point where `2 + 2 = 5` is printed.  Clearly this condition can never be satisfied.
<br><img src="imgs/chal4-ConditionAndUserInput.jpg" width="500"></br>

What's supposed to happen afterward is that the user input is converted into an integer.  Notice that only the first byte is used (meaning that there are really only 256 possible inputs).  Then the MD5 of the byte is taken.
<br><img src="imgs/chal4-UserInputMd5HourSaved.jpg" width="500"></br>

A series of checks using the current time occurs, each using some Base64-encoded text.  At the end of these checks, we see the hour being used again.  It indexes into an array which holds the Base64 decodes of the encoded strings in the above checks.  The 32-bits of binary are compared with the MD5 produced by our user input.  The user input must match one of the Base64 decodes, and that will be dependent on the hour.
<br><img src="imgs/chal4-CompareMd5.jpg" width="500"></br>

Next is another series of checks with Base64-encoded text.  These are used at the end to decrypt the email to the next challenge.

Now that we have an idea of how the program works, we can start working on the packed binary, since the unpacked binary will never produce working results.  With the knowledge that only 256 different inputs are possible, a simple bash script such as the following can be used to brute force the program:
```bash
i=0
while [ $i -lt 256 ]; do
  ./youPecks.exe $i
  i=$((i+1))
done
```

The number of iterations required to reach a solution varies depending on the hour.

<br><img src="imgs/chal4-Solved.jpg" width="500"></br>
