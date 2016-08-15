# PAN LabyREnth CTF - Windows Challenges

## Challenge #1

This binary has the file name "AntiD.exe".  This suggests that there will be some Anti-Disassembly or Anti-Debugging involved.

Running the program opens a CLI prompt that asks for a password.  It looks like a standard crack-me challenge.  We'll use a disassembler/debugger like IDA to move forward.

Right off the bat, we see that the file appears to be packed with UPX.  The standard UPX utility does not successfully unpack the binary, however, so we will have to do this manually.

Unpacking is not too difficult.  In IDA, we can see in the initial function where the `jmp` to the unpacked code occurs.  This is at the line:

`ups1:004091AC                 jmp     near ptr byte_401647`

After the jump, we can begin looking at the meat of the program.

We could step through the program to find that the user input is obtained through the function `sub_12B1380`.  But a quick shortcut I like to do with crack-mes that ask for user input through stdin involves the following process:

1. Run the program (either from the debugger, or run the program by itself and then attach with the debugger)
2. Pause the running program as it blocks awaiting your input
3. Switch back to the main thread in your debugger (a thread is injected to break execution and pass it back to the debugger)
4. View your call stack and identify where the return to the closest *user code* is (you should currently be in a library function such as `scanf`)
5. Set a breakpoint at the user code to where the user input function will return
6. Resume execution (if you get any exceptions, simply discard them)
7. Enter something into stdin and press Enter
8. The program should break on the breakpoint set in step 5 above.

Using this process, you should be able to get a quick handle on the user input.  Now we can analyze what happens with it.

After continuing to step through the program, we see that our user input passed to `sub_12B11B0`.  In this function, we can see a buffer at `ebp+var_2C` being filled byte-by-byte with some values.  Then a loop begins with some transformations on bytes from our user input along with several function calls in between.  The function calls make API calls to the following functions:

1. `CheckRemoteDebuggerPresent`
2. `FindWindow` (With argument `"OLLYDBG"`)
3. 'IsDebuggerPresent`
4. `rdtsc` (CPU instruction, not an API call)

Looks like we've identified our anti-debugging code.  To bypass these, we can simply patch them out or set conditional breakpoints (breakpoint scripts/actions) that will ensure that the program will not go toward the "exit" path.

Meanwhile, we see what operations are being performed on our input.  There is `xor eax, 33h`, `add edx, 44h`, `xor ecx, 55h`, and more.  Simply reverse these operations to identify what input will yield the key.

Oh, and if the program doesn't run, that's because it requires Microsoft Visual C++ 2015 Redistributable as a dependency.

The following Python code will solve this challenge:

```
import sys

key = [ord(i) for i in '8cf153a308d7dc48db0c3aee1522c4e5c9a0a50cd3dc51c739fdd0f83be8cc030643f7da7e65ae80'.decode('hex')]
key = [140, 241, 83, 163, 8, 215, 220, 72, 219, 12, 58, 238, 21, 34, 196, 229, 201, 160, 165, 12, 211, 220, 81, 199, 57, 253, 208, 248, 59, 232, 204, 3, 6, 67, 247, 218, 126, 101, 174, 128]
accs = [0]
for i in range(len(key)):
    accs.append((accs[i] + key[i]) & 0xff)

def solve(_input):
    s = []
    acc = accs[-1]
    for c in reversed(_input):
        acc = (acc - c) & 0xff
        b = (c ^ acc)
        b = (b + 0x66) & 0xff
        b ^= 0x55
        b = (b - 0x44) & 0xff
        b ^= 0x33
        s.append(chr(b))
    print "".join(reversed(s))

def unsolve(_input):
    acc = 0
    for curr_byte in [ord(i) for i in _input]:
        b = curr_byte
        b ^= 0x33
        b = (b + 0x44) & 0xff
        b ^= 0x55
        b = (b - 0x66) & 0xff
        b ^= acc
        acc = (acc + b) & 0xff
        print hex(b) + ' : ' + hex(acc)

if __name__ == '__main__':
    # unsolve("PAN")
    solve(key)
```

## Challenge #2

This neat challenge involves a piano keyboard that actually plays music.  With a challenge like this, it is logical to guess that pressing a certain sequence of keys will somehow provide us the key to the next challenge.

Static analysis shows us that this binary contains .NET managed code.  This means that we can use a tool like ILSpy to decompile it and hopefully retrieve something close to the source code.

This is exactly what we get.  A quick look through the `Form1` class in the `BabbySay` namespace reveals a method with this prototype:

`public void key_click(object sender, EventArgs args)`

Events are used in GUI applications to trigger certain callbacks, or functions that will execute as a reaction to some event.  It looks like this method will be called when a key is clicked.

We see in this function that the keys are checked along with a variable called `dat_state`.  When the condition is met (a certain key press at a certain `dat_state`), then the state is updated.  If a key press for a certain `dat_state` is not met, then `dat_state` goes back to 0.  It appears that we have a state machine, and we only need to write down the sequence and play the keys in that order to have something occur, that is, for the `Form1` object to invoke its `do_a_thing` method.  Pressing the keys opens up a scrolling banner with the key to the next challenge.

To make things easier, I simply opened up 2 instances of `notepad.exe`, placed them on the top and bottom of the window, and put numbers next to the keys so I would know which to click.

## Challenge #3

This challenge is somewhat simple.  It gives you references on how to solve it if you cause the code to go down the wrong path.  What we have here is a binary laced with anti-debugging code.  If you trip one of the anti-debugging methods, then the key will turn out wrong, and the program will not properly decrypt the file at the end.

Conditional breakpoints, or breakpoints with scripting actions, make this challenge a breeze.  The code tells you what path is correct, and what path is wrong.  All that is necessary is to set a breakpoint after each anti-debugging method that will cause the code to continue in the right path.  This can be setting the `eax` register to be non-zero if a zero will cause it to branch to the wrong area.  Alternatively, you could patch the code or manually run to these points and set `eip` to the correct code branches.

If you do everything correctly, then an image file will be decrypted and dropped on the filesystem.  The last task is to change the binary to ASCII characters.  The only way to do that is by hand by looking at the image (or OCR, but that might be more work.)

## Challenge #4

This challenge is called `JugsOfBeer`.  It was one of the tougher problems, judging by the number of people stuck on it looking at the progress chart.

Upon running the program, we see that it is GUI application that asks for input in a text box and a Validate button.  It looks like we will hae to enter a valid key and hit the button.

This program has a GUI interface, so our trick used in Challenge #1 will not work.  However, we can do something similar.  Your goal in these types of challenges should be to get a hold of the user input so that you can analyze what happens to it.  Since this is a GUI application, it most likely uses functions imported from `user32.dll`.  In the imports for this binary, we see a function called `GetDlgItemTextW` from `user32.dll`.  This sounds like what we're looking for, so we set a breakpoint at this function's entry.

So then similar to Challenge #1, we run the program again, enter some input, and hit the Validate button.  The debugger breaks!  After returning from this function, we now have a hold of our input.  It looks like our text came out in Unicode.

Immediately after obtaining our input, the program checks the length of the string.  There is this line which check if the string is of even or odd length:

`.text:000000013F0C1492 test    al, 1`

The program branches to the "wrong" area of code if the length is odd, so we know we must enter an even number of characters.

We see additional checks on the length, including:

- Must be > 0
- Must be >= 0x20

Then we see some strange things happening to our input including the following:

- Subtract 0x31 (add negative 0x31)
- Branch to the "wrong" code if greater than 2 (unsigned comparison)

So our input must be something that is in the set `{0, 1, 2}` when subtracting 0x31 (or an ASCII `1` character).  It looks like our input must be the ASCII characters `1`, `2`, `3`.  So far we have the following information about what our input must look like:

- More than 0 characters
- More than 0x20 characters
- Even number of characters
- Only characters `1`, `2`, and `3`

Finally, our input is sent to `sub_13F0C1750` for processing.  The algorithm looks straightforward, but complex to reverse.  After spending quite a bit of time on it, I remembered a great piece of advice from my great co-worker Mike Zeberlein: "Google everything."  So considering this algorithm, what did I have?

- 3 options for input
- Some interesting constants: `0xd`, `7`, and `0x13` (That is: 13, 7, and 19)
- The result of the algorithm need to end in `0xa` in one memory location and `0xa` in another (That is: 10 and 10)
- A binary called *JugsOfBeer*

In the results: http://sbjoshi.blogspot.com/2008/01/water-jug-puzzle.html

It all makes sense now!  We have 3 jugs of beer of sizes 13, 7, and 19.  The ones with sizes 13 and 7 are completely filled, and we need to use these jugs to evenly divide the 20 units into 2 jugs filled with exactly 10 units.

The blog above provides exactly the solution we need for this challenge.  In our input, pairs of numbers mean to transfer water from one jug to another.  For example, `31` means to transfer whatever is in `3` to `1` if the destination is filled all the way, then the remainder stays in the source.

Entering the correct sequence causes the key to the next challenge to be displayed on the screen.

Moral of the story: `Google everything!`

## Challenge #5

This one really should have been Challenge #1.  Running the application, we see a window with 3 sliders, one each for RGB (Red, Green, Blue?), and then a button to "Check" our answer.  It looks like we will have to provide the correct position on all 3 sliders to get our solution.

This is a .NET managed code binary, so we can open it up in ILSpy.  The method `private void btnCheck_Click(object sender, EventArgs e)` is called upon clicking the Check button, and we see that a certain condition must be met in order for a `MessageBox` to be displayed.

The condition is:

`value + num - value2 + value * value * value2 - value3 == value2 * (value3 * 34 + (num2 - value)) + 3744 && value > 60`

Where the `value`s come from the values of the RGB sliders.  We also see that the method `private string szB(int iDummy1, int iDummy2, int iDummy3, byte[] bArrayA, int iDummy4, int iDummy5)` is used to generate the text that will be displayed in the `MessageBox`.  Taking a closer look at this method, we see the following line:

`bArrayA[expr_0E_cp_1] ^= (byte)(this.c ^ iDummy2);`

Here, `iDummy2` is passed as an argument, and *it never changes!*  It is a static XOR key.  We have a tool called `xorsearch` for that (https://blog.didierstevens.com/programs/xorsearch/)

So we run `xorsearch RGB.exe "PAN{"`, and boom, we have our answer.  All of that talk about sliders and values and conditions was all fluff :)

## Challenge #6

This challenge's binary was called `ShellCode.exe`.  It does not import any functions statically.  However, we see it use the function hashing technique to obtain pointers to functions from DLLs which it obtains handles from through the Process Environment Block, or PEB.  This is easily recognized through the following code:

```
mov     eax, large fs:30h ; This is the tell-tale sign
mov     eax, [eax+0Ch]
mov     eax, [eax+14h]
mov     eax, [eax]
mov     eax, [eax]
mov     eax, [eax+10h]
retn
```

After obtaining a handle to DLLs using this technique, pointers to functions can be obtained by walking the DLL's export table.  The following functions are imported:

| Function | DLL |
| - | - |
| VirtualAlloc | Kernel32 |
| GetUserDefaultUILanguage | Kernel32 |
| GetVersion | Kernel32 |
| GetLocalTime | Kernel32 |
| MessageBoxA | User32 |

It looks like our key will be output in a MessageBox again.  But what needs to happen to get there?  Well, after a call to `sub_401000`, there is a check for the characters `PAN{`.  It looks like `sub_401000` will somehow decrypt a buffer to output the key.

The first call to `VirtualAlloc` allocates a buffer.  A call to `GetUserDefaultUILanguage` yields some numbers that are placed in this buffer.  Several of the imported functions are used to obtain data to place in this buffer.  However, most of the buffer is filled with constant values.  It appears that the our system settings/properties are being used to generate certain values that are put in this buffer which is fed to the decryptor.

Let's take a closer look at the decryptor to see what we can do to reverse this. In `sub_0040106D`, we see what appears to be the RC4 Key Scheduling Algorithm (KSA).  I feel sorry for anyone who tries to reverse this byte-by-byte, but I guess the only way to know that that isn't going to work is experience

So how are we supposed to tackle something that's cryptographically secured in a reasonable time?  Well, we know that most of the key is static.  In fact, only a small number of bytes come from our system's properties, so performing an exhaustive key search (brute force) shouldn't take too much time, as there are only a finite number of system locales, Windows versions, hours in the day, etc.

The first 2 values come from the call to `GetUserDefaultUILanguage` which returns a LANGID.  Some information on LANGIDs is here:

https://msdn.microsoft.com/en-us/library/windows/desktop/dd318691(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

The lower byte (primary language) of LANGID must be 0 for the program to proceed.  The sublanguage is used in the key, and the possible values for the given primary language are in the set `{0, 1, 3, 4, 5}`.  We will try those in our exhaustive key search.

Next is the call to `GetVersion`.  There are only a finite number of Windows versions.  We have to consider both the Major version and the Minor version since they are each used in the key.  A list of Windows versions starting from Windows 2000 is listed here:

https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx

We will try these 14 possibilities in our exhaustive key search.

The next item that will determine what goes into our key is a `SYSTEMTIME` structure which is filled with a call to `GetLocalTime`.  Here, we see that the month, day, and hour are used.  This provides roughly `12 x 31 x 24 = 8928` combinations.

The last thing used to determine what goes into the key depends on whether a debugger is attached to the process.  This information is also gathered from the PEB using the following code:

```
mov     edx, large fs:30h
mov     dl, [edx+2]     ; PEB.BeingDebugged
```

This is either a `1` or a `0`, and this value is added with 0x69 and placed into the key.

So each of the following items contributes the following possibilites to our keyspace:

| Item | Combinations |
| - | - |
| UI Language | 5 |
| Windows Version | 14 |
| Month | 12 |
| Days | 31 (just use the max rather than playing around with date logic) |
| Hours | 24 |
| Debugger Presence | 2 |

This is about 1,249,920 combinations which is very doable for practically any computer.

Ok, so I had a small bump in the road: brute force wasn't working for me.  The only thing I imagined could be causing an issue was the UI Language.  Maybe I didn't understand the documentation correctly, but anyway, it was only a single byte.  Instead of trying values `{0, 1, 3, 4, 5}`, I just tried `0` to `255`.  And like magic, it worked.  There were a few false-positives since "PAN" is only 3 characters long.  The following code was used to produce the key:

```
import crypt # A custom library

enc = [186, 175, 77, 85, 60, 227, 3, 34, 176, 223, 243, 211, 87, 208, 225, 64, 249, 19, 31, 186, 141, 18, 241, 255, 72, 194, 142, 0, 253, 84, 151, 157, 117, 113, 48, 143, 67, 40, 254, 105, 54, 71, 143, 162, 239, 73, 116, 124, 225, 76, 111, 79, 212, 130]

def MakeKey():
    xx = 0
    key = bytearray('b00!\x00\x00\x00\x00\x00\x00\x00')

    for a in range(len(months)):
        print "Month = %d" % months[a]
        key[4] = (months[a] + 0x2d) & 0xff
        for b in range(len(days)):
            print "Day = %d" % days[b]
            key[5] = (days[b] + 0x5e) & 0xff
            for c in range(len(hours)):
                key[6] = (hours[c] + 0x42) & 0xff
                for d in range(len(versions)):
                    major, minor = versions[d]
                    key[8] = (minor + 0x3f) & 0xff
                    key[7] = (major + 0x3c) & 0xff
                    for e in range(len(debugging)):
                        key[9] = (debugging[e] + 0x69) & 0xff
                        for f in range(len(sublang)):
                            xx += 1
                            key[0x0a] = (sublang[f] + 0x5e) & 0xff

                            # Decrypt and check
                            k = "".join([chr(i) for i in key])
                            ee = "".join([chr(i) for i in enc])
                            dec = crypt.rc4_decrypt(k, ee)
                            if dec[ : 3] == "PAN":
                                print "Found key: %s" % k
                                print dec
                                print "sublang: %d" % sublang[f]
                                print "debugging: %d" % debugging[e]
                                print "version: %s" % str(versions[d])
                                print "Time: %02d/%02d %02d:00" % (months[a], days[b], hours[c])
    print "Tried %d combinations" % xx



if __name__ == '__main__':
    MakeKey()
```

Results:

```
Month = 12
Day = 13
Found key: b00!9kLA@jf
PAN{<key here>}
sublang: 8
debugging: 1
version: (5, 1)
Time: 12/13 10:00
Day = 14
Day = 15
```

## Challenge #7

In this challenge, we are presented with a PCAP file along with a binary that supposedly produced it.  In the PCAP, we see TCP connections being made and 1 character being sent at a time.  The last 2 characters are `==`, so you should immediately start thinking "Base64".

So what's the easiest way to gather 175 characters out of a PCAP?  `tcpflow`, of course!  Since there are so many connections, this is goinig to get messy.  So I created a subfolder underneath the PCAP and `cd`'d to it.  Then, I simply ran `tcpflow -r ../G0blinKing.pcap`, and each TCP connection (only 1 character long) was output to an individual file.  The easiest way to string them all together is, of course, the `cat` command.  So you can concatenate them all together using the following: `cat *08080 >> catted` to put the whole string in the file `catted`.

Now we have a Base64 string.  Unfortunately, running a Base64 decode doesn't seem to reveal anything.  It's time to start looking at the binary.

Looking through the disassembly, the binary appears to do the following:

1. Open a file called `file.txt` in the current directory and read all the data (`sub_411316`)
2. Perform a transformation on the data using some algorithm with the key `AWildKeyAppears!` (`sub_411127`)
3. Encode the result with Base64 (`sub_4111B3`)
4. Transmit each character over the network (`sub_411357`)

But I thought Base64-decoding wasn't working?  How do you know it's Base64?  Well, the tell-tale signs of Base64 are the following:

1. XOR with 0x3f
2. SHR with 2
3. MOVing the constant 0x3d (`=`) into a buffer
4. Indexing into a constant byte array (`byte_41A000`)

The constant byte array points to the string `qtgJYKa8y5L4flzMQ/BsGpSkHIjhVrm3NCAi9cbeXvuwDx+R6dO7ZPEno21T0UFW`.  It appears that we have Base64 with a custom alphabet on our hands.

To see some quick code that can be used to perform a Base64 encode or decode, see the code snippet below.  Decoding the network traffic results in the following:

```
0000000: 4b0a 142a 2844 13dc 6be3 1a95 f41f bc0a  K..*(D..k.......
0000010: 71b6 2601 7730 90bb 8c5b 42ac cfe1 0f18  q.&.w0...[B.....
0000020: c764 0466 7f05 9bc4 4442 4fa1 dee5 cad5  .d.f....DBO.....
0000030: 5fb0 f578 2f1f fac5 46a6 90fe 7f69 62a0  _..x/...F....ib.
0000040: 75bd 5dd9 9567 aef0 eb45 05dd d9ac 9025  u.]..g...E.....%
0000050: ccce 49c0 8cb0 a388 ba85 136a 64c9 166b  ..I........jd..k
0000060: 7d4e 315d bc7c 0529 27eb 8690 0bf2 dff3  }N1].|.)'.......
0000070: 3472 5bb0 7f64 e236 71b6 2601 7730 90bb  4r[..d.6q.&.w0..
0000080: 8c5b 42ac cfe1 0f18 7f10 1034 090e f711  .[B........4....
0000090: 4b0a 142a 2844 13dc 6be3 1a95 f41f bc0a  K..*(D..k.......
00000a0: 71b6 2601 7730 90bb 4449 4e47 5041 44    q.&.w0..DINGPAD
```

It looks like there is some "padding" at the end.  The data is mostly unintelligible, but the "DINGPAD" at the end tells us that we're on the right track.  So now it looks like all we have to do is reverse the custom algorithm to obtain our key.

The meat of this encoding algorithm occurs in the function `sub_41100F`.  In C, this function would have the following prototype:

`void sub_41100F(int nrounds, char *input, char *key);`

The parameters are the following:

- `nrounds` is a constant 0x20 which determines the number of rounds iterations that will be performed
- `input` is a pointer to 8 bytes of data that will be transformed when the function returns
- `key` is the constant string `AWildKeyAppears!`

In this function, we see some variables, which I call "registers" being set:

```
mov     [ebp+reg1], 0BADA55h
mov     [ebp+reg2], 9E3769B9h
mov     [ebp+reg3], 4913092h
mov     [ebp+reg4], 12345678h
mov     [ebp+reg5], 0DEADBEEFh
```

Then we have some output registers which I call `out1` and `out2` which are `int`s that will replace the 8 bytes of our `input`.  Additionally, there is an `int` variable at `ebp-68h`, which I call `acc` for accumulator.

The algorithm takes our input and performs several shifts and XORs to produce the output data.  This looks difficult to reverse, until you realize the following:

- `reg5` is initialized with the value `0xDEADBEEF`, probably because it isn't used
- `reg4` is changed in every iteration of a subloop, but its value has no imact on our output
- `reg1` is in the same boat as `reg4`
- `reg2`'s value is constant
- `reg3` is in the same boat as `reg1` and `reg4`
- Sorry for doing that out-of-order :)

So this doesn't look too tough after all.  We even see that the inner loop is completely useless and has no bearing on the output.  We should be able to reverse this.

Ahh, but as we try to reverse it, we realize that we don't have a starting value for `acc`.  That depends on its previous value, but who knows what the hell that was after 0x20 rounds.  Ok, I do :)  `acc` depends on `reg2` and its previous value.  `acc` starts at 0, and `reg2` is constant.  The code for updating acc looks like:

`acc = (acc + reg2 + 0x1000) & 0xffffffff`

And this happens 0x20 times.  So to find the value at the end of the algorithm (the start of the reverse algorithm), we just perform this operation 0x20 times.  Once we do this, we have our answer.  The code below produces the key.

I implemented the algorithm forward in order to understand how to implement it backward.  The `forwards` function is a "simplified" version of the `forward` function.  Likewise for the `backwards` function.  It was through the simplification process that I realized `acc` depends only on itself and a constant.

```
import struct
import sys

catted_pcap = 'B6XGLACYYUdwodupUtF0geaE5NKnf5gTiKxgwfWCJdi8Iq/b36ShdY/gs18m2VwpkTJPmg03FDpavvJF3EcAX8SUkrbpI1T61ZGKnrbD9gkf79eqi4giA4uKYEv9O/Iw3Godkhd0tB9e1ojQgW4307/OSTtWIzyEVhHbqkV694+fSZLD7FYMa80QYJQ5JRV/B6XGLACYYUdwodupUtF0geaE5NKnf5gT/Ycz/Ptt/q=='

ALPHABET = 'qtgJYKa8y5L4flzMQ/BsGpSkHIjhVrm3NCAi9cbeXvuwDx+R6dO7ZPEno21T0UFW'

import string
import base64

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET = ALPHABET
ENCODE_TRANS = string.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = string.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)

def encode(input):
  return base64.b64encode(input).translate(ENCODE_TRANS)

def decode(input):
  return base64.b64decode(input.translate(DECODE_TRANS))

def forwards(rounds, input, key = "AWildKeyAppears!"):
    reg2 = 0x9E3769B9   # Only ever has 1 value
    acc = 0             # Only changed by prev value and reg2
    out1 = struct.unpack("<I", input[ : 4])[0]
    out2 = struct.unpack("<I", input[4 : 4 + 4])[0]
    for i in range(rounds):
        eax = (out2 << 4) & 0xffffffff
        ecx = out2 >> 5
        eax ^= ecx
        eax = (eax + out2) & 0xffffffff
        edx = acc
        edx &= 3
        esi = acc
        esi = (esi + struct.unpack("<I", key[edx*4 : edx*4+4])[0]) & 0xffffffff
        eax ^= esi
        eax = (eax + out1) & 0xffffffff
        out1 = eax

        eax = reg2  # Const
        acc = (acc + eax + 0x1000) & 0xffffffff # Know the end value: 20 * (self + eax + 1000h)
        eax = (out1 << 4) & 0xffffffff
        ecx = out1 >> 5
        eax ^= ecx
        eax = (eax + out1) & 0xffffffff
        edx = acc >> 0xb
        edx &= 3
        esi = acc
        esi = (esi + struct.unpack("<I", key[edx*4 : edx*4+4])[0]) & 0xffffffff # edx is 0, 1, 2, or 3
        eax ^= esi
        eax = (eax + out2) & 0xffffffff
        out2 = eax
    output = bytearray()
    output += struct.pack("<I", out1)
    output += struct.pack("<I", out2)
    return output

def backwards(rounds, output, key = "AWildKeyAppears!"):
    out1, out2 = struct.unpack("<II", output)
    reg2 = 0x9E3769B9   # Only ever has 1 value
    acc = 0
    #Calculate acc
    for i in range(rounds):
        acc = (acc + reg2 + 0x1000) & 0xffffffff

    for i in range(rounds):
        edx = (acc >> 0xb) & 3
        esi = (acc + struct.unpack("<I", key[edx*4 : edx*4+4])[0]) & 0xffffffff # esi is good up to here
        eax = (out1 << 4) & 0xffffffff
        ecx = out1 >> 5
        eax ^= ecx
        eax = (eax + out1) & 0xffffffff # eax is good up to here
        eax ^= esi
        out2 = (out2 - eax) & 0xffffffff    # out2 is good up to here

        acc = (acc - reg2 - 0x1000) & 0xffffffff

        edx = acc & 3
        esi = (acc + struct.unpack("<I", key[edx*4 : edx*4+4])[0]) & 0xffffffff
        eax = (out2 << 4) & 0xffffffff
        ecx = out2 >> 5
        eax ^= ecx
        eax = (eax + out2) & 0xffffffff
        eax ^= esi
        out1 = (out1 - eax) & 0xffffffff
    _input = struct.pack("<I", out1)
    _input += struct.pack("<I", out2)
    return _input


def forward(rounds, input, key = "AWildKeyAppears!"):
    reg1 = 0xBADA55
    reg2 = 0x9E3769B9   # Only ever has 1 value
    reg3 = 0x4913092    # Never really used?
    reg4 = 0x12345678   # Only changed by prev value
    reg5 = 0xDEADBEEF   # Never used
    acc = 0             # Only changed by prev value and reg2
    out1 = struct.unpack("<I", input[ : 4])[0]
    out2 = struct.unpack("<I", input[4 : 4 + 4])[0]
    for i in range(rounds):
        eax = (out2 << 4) & 0xffffffff
        ecx = out2 >> 5
        eax ^= ecx
        eax = (eax + out2) & 0xffffffff
        edx = acc
        edx &= 3
        esi = acc
        esi = (esi + struct.unpack("<I", key[edx*4 : edx*4+4])[0]) & 0xffffffff
        eax ^= esi
        eax = (eax + out1) & 0xffffffff
        out1 = eax
        eax = reg1
        eax = (eax + 0xffc) & 0xffffffff
        reg1 = eax
        for j in range(8, 0x20):
            eax = (reg4 << 3) & 0xffffffff
            reg4 = eax
            eax = reg1
            eax = (eax - 0x40) & 0xffffffff
            reg1 = eax
            eax = reg3
            eax = (eax - 8) & 0xffffffff
            reg3 = eax
        reg5 = 0x40
        eax = reg2  # Const
        ecx = acc
        edx = (ecx + eax + 0x1000) & 0xffffffff
        acc = edx
        eax = (out1 << 4) & 0xffffffff
        ecx = out1 >> 5
        eax ^= ecx
        eax = (eax + out1) & 0xffffffff
        edx = acc >> 0xb
        edx &= 3
        esi = acc
        esi = (esi + struct.unpack("<I", key[edx*4 : edx*4+4])[0]) & 0xffffffff # edx is 0, 1, 2, or 3
        eax ^= esi
        eax = (eax + out2) & 0xffffffff
        out2 = eax
    output = bytearray()
    output += struct.pack("<I", out1)
    output += struct.pack("<I", out2)
    return output

if __name__ == '__main__':
    content = decode(catted_pcap)
    reassem = ""
    for i in range(len(content)/8):
        sl = content[i*8 : i*8 + 8]
        b = backwards(0x20, sl)
        reassem += b
    print reassem
```

Result:

```
PADDINGPADDINGPADDINGPADDINGPADDINGPADDINGPADDINGPADDINGP
PAN{<key here>}
PADDINGPADDINGPADDINGhibobPADDINGPADDINGPADDINGPAD
```
