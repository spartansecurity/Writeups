#Challenge 7
####Binary: YUSoMeta
####Type: PE Executable (.NET)
####Arch: x86

##Armen's Solution
Using PEiD reveals that the binary is .NET.  Using ILSpy to decompile it shows us obfuscated code.  Some symbols are not even printable ASCII characters.
<br><img src="imgs/chal7-Obfuscation.jpg" width="500"></br>

The program de4dot can be used to unobfuscate it.  Looking through the Main() function of the unobfuscated code, we see that our input is compared with a string produced by Class3.smethod_0() concatenated with '_' and a string produced by Class3.smethod_3().  Following these static methods shows that bytes of code in the binary are used to produce these strings.  This means that our unobfuscated binary will change the key needed for the next email to be output.  Otherwise, the Rijndael decrypt will fail.

The Main() function looks very straightforward.  Ultimately, the user input is string-compared against a given value, and if there is a match, then the user value is input, and the email to the next challenge is output.  It would be nice if the variable `b` were passed to Class3.smethod_1 rather than `text`.
<br><img src="imgs/chal7-Unobfuscated.jpg" width="500"></br>

So the plan of action is as follows:
1. Swap the variable positions for `text` and `b` (so that Console.ReadLine().Trim() is saved to the location of `b`, and Class3.smethod_0() is saved to the location of `text`)
2. Ignore/nop the *if* conditional
3. ???
4. Profit!

To do this, we open the unobfuscated version of the binary in IDA as Microsoft.Net Assembly.  We can see the methods being called and stored into variable locations.
<br><img src="imgs/chal7-VariableLocations.jpg" width="500"></br>

If we look at the branch that is taken if the comparison succeeds, we can see the variable at Location 2 being passed to Class3.smethod_1 to decrypt the next email.  If we switch the locations, then the text that our input is verified against (which we assume is always correct) will be used instead.  However, we must do this in the original binary to ensure that the decryption works properly.
<br><img src="imgs/chal7-VariableLocationDecrypted.jpg" width="500"></br>

Identifying the location where the input is taken is more difficult because of the obfuscation.  The 0x5F character makes a good anchor point.  We can see the user input being stored with `stloc.2` above, and the output of `Class3.smethod_0 + '_' + Class3.smethod_3()` is stored with the instruction `stloc.3`.  If we highlight the instruction, we see in the hex dump that it is made of the byte 0x0d.  Highlighting the `stloc.2` instruction, we see that it is made of the byte 0x0c.  We patch these bytes in IDA to swap the location where these variables are stored.
<br><img src="imgs/chal7-Instruction.jpg" width="500"></br>

Next, we need to remove the branch.  We want execution to fall through to the location where the user input (now the constant used for verification) is pushed to Class3.smethod_1() and the next email is written to the screen.  We can do this by replacing the string comparison (and its arguments) and the branch with nop instructions.  nop instructions are each one 0x00 byte.  The patched code can be seen in the screenshot below.
<br><img src="imgs/chal7-Patch.jpg" width="700"></br>

Running the patched program allows us to input anything, and the email to the next challenge will be spit right out.
<br><img src="imgs/chal7-Solved.jpg" width="500"></br>
