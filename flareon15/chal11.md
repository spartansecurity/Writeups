#Challenge 11
####Binary: CryptoGraph
####Type: PE Executable
####Arch: x86

##Josh's Solution
This level was by far the most difficult in the challenge. At least, for me. After a combined total of ~30 hrs of painful reversing, however, I finally solved it. I lost a lot of time trying to understand everything the encryption did which turned out to be a trap.
<br><br><img src="imgs/trap.png" width="200"><br>
Guess I should've listened to General Ackbar.

Fortunately, to solve this challenge, you don't really need to understand what everything does. You just need to understand enough to get the gist of how the program works and how what functions you do understand interact with each other. Half of reversing is just learning to block out the white noise and focusing on what's important: what happens to the data you can control.
 
When I ran the program without any arguments, the program sent back a message, "The number of parameters passed in is incorrect." Looking at the disassembly, I noted that it uses the WinAPI `CreateFile()` function to return a handle to a file it creates, named `secret.jpg`. The program also takes in 1 command line argument and if it is an integer, returns its hex equivalent which is subsequently passed into the function at address 0x401910.
<br><img src="imgs/chal11-main.png" width="500"><br>
I also noticed after running several trials with different numbers as the command line argument, that the program always seems to hang and never naturally terminates. After terminating the program forcefully, I notice it always outputs an empty `secret.jpg` file. My guess, then, was that I had to enter the correct argv[1] which would produce a valid .jpg file, hopefully containing the solution. First, I had to figure out what was causing the program to hang. 

For my test case, I ran the program in a debugger with `50` as argv[1]. Looking at the disassembly again in IDA, I traced the problem to function 0x401170 which contains a really long loop. The loop's jnz exit condition uses an outrageous number like 0xDBE8E5DB, or 3,689,473,499 in decimal which is slowly decremented bit by bit. 
After playing around with argv[1] for a bit, I noticed that different inputs change this exit condition number. So instead of having to iterate through the loop 0xDBE8E5DB times, if I changed argv[1] to `200`, I would only have to iterate through it 0xC53A3550 times!
<br><img src="imgs/chal11-not-gonna-finish-2.png" width="300"><br>
<br><img src="imgs/chal11-not-gonna-finish-5.png" width="400"><br>  
Yeah, not very helpful. I wasn't going to wait for that loop to finish, especially not while running the program on a really crappy Windows XP VM. So I had to try a different approach.
Tired and confused, I decided to take a step back and see exactly how argv[1] was affecting that exit condition value by following it. Perhaps there was a value I could use as argv[1] that would generate a reasonable exit condition? After all, at that point in the level, it was the only element of the program that I knew I could control.

While setting an initial hardware r/w bp on argv[1] and following the addresses where it is read or copied from, and setting bp's on those addresses and following where those are read or copied from, and so on and so forth, I noticed only the lower byte of the hex number ever gets used. 
This observation implies something useful: that one of the decimal numbers between 0 and 255 has to be correct and allow me to get through the loop without hanging.

256 numbers is easily brute-forceable so I whipped up a quick IDAPython script to find the correct value:
```python
from idaapi import *

def testval(i):
	StartDebugger("",i,"")
	GetDebuggerEvent(WFNE_SUSP, -1)
	continue_process()
	GetDebuggerEvent(WFNE_SUSP, -1)
	eax = GetRegValue("EAX")	
	GetDebuggerEvent(WFNE_SUSP, -1)
	StopDebugger()
	GetDebuggerEvent(WFNE_SUSP, -1)
	print eax
	return eax

#just set the bp manually. it's faster.
#AddBpt(0x004011D0)
#GetDebuggerEvent(WFNE_SUSP, -1)

for i in range(0,255):
	f = open('input.txt', 'r+')
	f.write(str(i))
	f.close()
	print "trying "+str(i)
	a = testval(str(i))
	if (a<0x7ffff):
		print i
		break
```
After grabbing a cold brew and getting a couple minutes of fresh air, I came back to the script which had finished and stopped at the decimal number 205. When 205 is used as argv[1] the loop only has to decrement from 0xFFFF or 65535, which, even on my slow ass VM, is instantaneous. 
However, after I exited this loop, I came across another obstacle. The function this loop is contained within is called within an outer loop at the end of function 0x4015D0 which depends on an exit condition which increments a value until it hits 0x20, or 32. 
<br><img src="imgs/chal11-not-gonna-finish-3.png" width="300"><br>
And with each iteration, the value the exit condition references in the previous loop, 0xFFFF, increases substantially. So, it wasn't feasible, at least on my Windows VM, to wait for the entire loop to finish. Therefore, I was left with only two options: 1) buy a super computer 2) find a shortcut. I decided to go with 2). 

As it turns out, you don't have to wait for the entire loop to finish to generate a valid .jpg file. You can actually binary patch this loop to end it prematurely and still get a valid jpg file. You just need to figure out the exact number of times to let the loop run before exiting it. 

To do this, I first observed that the number of times the loop runs affects the value of a variable, [EBX+0x638], in function 0x401B60 upon which, several arithmetic calculations are performed to determine the flow of execution in this function. 
<br><img src="imgs/chal11-401b60-num.png" width="300"><br>
This function appears to decrypt the data that is later written to the .jpg but only does so properly if the function call at address 0x401C45 which executes the function @ 0x401B20 can be reached. In order to do this I had to find the correct number of times to iterate through the loop in order to produce a variable which would allow the flow of execution to reach 0x401C45.
<br><img src="imgs/chal11-call-401b20.png" width="500"><br>
After following the disassembly, and getting confused by Hex-Rays, I was able to reduce the problem of finding the variable, x, to the following: given a number x s.t. 0x0 < x < 0x7fffffff, the result of right shifting x by 0x18 != 0, and the result of right shifting x by 0x1a == 0. So now we have several constraints to play with, and what better way to find a number that satisfies these constraints than with our favorite SMT solver, Z3?
```python
#!/usr/bin/python
from z3 import *

x = BitVec('x', 32)

s = Solver()
s.add(x>0)
s.add(x<0x7fffffff)
s.add(x>>0x18 != 0)
s.add(x>>0x1a == 0)

print s.check()
print s.model()
```
Upon completion, this Z3 script reveals that the constraints can all be satisfied by the decimal number 33554432, or 0x2000000. So putting everything together, we now need to find the number of iterations of the loop in function 0x4015D0 to allow that will set the variable in function 0x401B60 to the value 0x2000000. 

After playing around with different exit conditions for the loop, I noticed a pattern and quickly figured out that I needed to let the loop run until it hit 0xB. So, I binary patched the loop condition to reflect this by changing the 0x20 to 0xB and let the program run to completion after passing it an exception. 
<br><img src="imgs/chal11-patched.png" width="400">  
Finally when I checked my file directory after doing this, I found a valid `secret.jpg` waiting for me. 
<br><img src="imgs/chal11-solved.png" width="300"><br>
