##Josh's Solution
When I first executed the program, nothing appeared to happen. Upon closer inspection in Anubis, however, I discovered it created 2 files: c:/windows/system32/ioctl.exe and a kernel driver c:/windows/system32/challenge.sys
<br><img src="imgs/chal10-anubis.png" width="500"><br>
Then, looking through the program loader.exe in IDA Pro I noticed it was or contained an autoit script. I then decompiled this script by opening loader.exe in exe2aut. In the decompiled code, I noticed a couple calls to the function "dothis()". 

```
FileInstall("ioctl.exe", @SystemDir & "\ioctl.exe")
$nret = dothis("0x96c581bc009905e76931875a583f97a738b764eb67f35c802194bf86123b943d1907619488a31a26cf29ba5f5e57ed5c5a37cb5d67dc2020a7e6d55cadefba32aba3ed77f0e18e41a571e74a8a7614a895d7c8827c46028761994543bf449138c65a6e7b5039792c85be5b4998c9950d2497f73cd88d186a6bffe3634bd250ec59e2", "flarebearstare")
If $nret Then
	If dothis("0x96d587b8139933d17e3598505e729da736bb66aa6cfa5180289fb6845530", "flarebearstare") Then
		dothis("0x9aee96b50da818d16f368556131aecfc69ef21a440f24fcc6bd1f3bd1e76db69574a6c8d81ed53688a7eaa364e53fd0700", "flarebearstare")
	EndIf
EndIf

Func decrypt($data, $key)
	Local $opcode = "0xC81001006A006A005356578B551031C989C84989D7F2AE484829C88945F085C00F84DC000000B90001000088C82C0188840DEFFEFFFFE2F38365F4008365FC00817DFC000100007D478B45FC31D2F775F0920345100FB6008B4DFC0FB68C0DF0FEFFFF01C80345F425FF0000008945F48B75FC8A8435F0FEFFFF8B7DF486843DF0FEFFFF888435F0FEFFFFFF45FCEBB08D9DF0FEFFFF31FF89FA39550C76638B85ECFEFFFF4025FF0000008985ECFEFFFF89D80385ECFEFFFF0FB6000385E8FEFFFF25FF0000008985E8FEFFFF89DE03B5ECFEFFFF8A0689DF03BDE8FEFFFF860788060FB60E0FB60701C181E1FF0000008A840DF0FEFFFF8B750801D6300642EB985F5E5BC9C21000"
	Local $codebuffer = DllStructCreate("byte[" & BinaryLen($opcode) & "]")
	DllStructSetData($codebuffer, 1, $opcode)
	Local $buffer = DllStructCreate("byte[" & BinaryLen($data) & "]")
	DllStructSetData($buffer, 1, $data)
	DllCall("user32.dll", "none", "CallWindowProc", "ptr", DllStructGetPtr($codebuffer), "ptr", DllStructGetPtr($buffer), "int", BinaryLen($data), "str", $key, "int", 0)
	Local $ret = DllStructGetData($buffer, 1)
	$buffer = 0
	$codebuffer = 0
	Return $ret
EndFunc

Func dothis($data, $key)
	$exe = decrypt($data, $key)
	$exe = BinaryToString($exe)
	Return Execute($exe)
EndFunc
```
I printed the outputs of those functions to message boxes which revealed that "ioctl.exe" was executed with the parameter "22E0DC" which I assumed was the IO control/request code. 
<br><img src="imgs/chal10-ioctl-1.png" width="500"><br>
After setting up kernel debugging, I was able to set a bp in the challenge.sys kernel driver on the jump table I found which redirects the lpr from the request code to its correct handler. I then sent the IOCTL call to the kernel driver with the code "22E0DC" and traced it down the jump table into its handler function. The IOCTL handler function consisted of a large sequence of "and" instructions and branches.
Essentially, this function is responsible for determining the bits of a string. Decoding the string bit-by-bit produces the string, "try this ioctl: 22E068". I then sent another IOCTL call using "22E068" as the control code and traced it to what appeared to be a TEA decryption algorithm.
Before the PC reaches the TEA decryption algorithm, however, it goes through a massive function which passes 3 arguments into another function: the key, an int which is later used to determine the number of rounds the decryption algorithm is iterated through, and the address of the buffer to be decrypted. The next function passes chunks of the data in the buffer into the actual TEA decryption algorithm in multiple rounds. After running a couple trials with WinDbg I noticed that the data contained within the buffer the TEA decryption algorithm decrypts changes with each runtime. However, the key and the number of rounds remain the same. After looking closer at the location of the buffer that is passed into the decryption function I x-ref'd each byte and noted they all contained constant values before being mutated by presumably the aforementioned massive function in the control code handler.
Putting the bytes of the xref'd bytes together gave me
567FDCFAAA2799C46C7CFC926161471A19B963FD0CF2B620C02D5CFDD97154964F43F7FFBB4C5D31
which I hoped would produce something meaningful if passed into the TEA decryption function. 
From there, it was a simple matter of performing in-memory patching w/WinDbg of the contents of the buffer that get passed into the TEA decryption algorithm at runtime and examining the result to obtain the solution. 
