#Challenge 11                              
####Binary: challenge, sender
####Type: PCAP, PE Executable
####Arch: x86

##Josh's Solution

The challenge contains both a challenge.pcap file and a sender.exe file.

Upon examining the pcap file, I noticed multiple HTTP POST packets being sent, each containing 4 bytes of ASCII characters in the body:

![pcap 1](https://github.com/conceptofproof/flareon15/raw/master/imgs/chal5-pcap-1.png)

![pcap 2](https://github.com/conceptofproof/flareon15/raw/master/imgs/chal5-pcap-2.png)

Putting all the 4 bytes together produces what appears to be the base-64 encoded string, `UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW==`

I tried base-64 decoding the string, but it simply produced gibberish.

Looking at the sender.exe file, I noticed the program takes user provided input and adds each character of the user input string to each corresponding character in the string "flarebearstare" and replaces the original character with the result. If the length of the user input string is greater than the length of "flarebearstare", after adding the last "e" in "flarebearstare" to the corresponding character in the user input string,"flarebearstare" is iterated through again from the beginning, and the next character in the user input string is added to "f", the following character after that is added to "l", and so on and so forth.

![chal5 flarebearstare](https://github.com/conceptofproof/flareon15/raw/master/imgs/chal5-flarebearstare.png)

![chal5 mutate](https://github.com/conceptofproof/flareon15/raw/master/imgs/chal5-mutate.png)

The resulting mutated string then appears to be base-64 encoded and the result is sent as a series of HTTP POST requests. However, I noticed that the base-64 encoding scheme appeared to be slightly different than normal. Sender.exe uses an alphabet structure that switches the order of lower-case letters and upper-case characters. 

![chal5 alphabet](https://github.com/conceptofproof/flareon15/raw/master/imgs/chal5-alphabet.png)

So, the program base-64 encodes the mutated user input, but switches the case of each letter. So, the actual base-64 encoded string that needs to be reversed is `udyS1d7BnMDe1O3G5MS1v6rRycvVodjf1dPXktXaj9XUzw==` rather than `UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW==`. 

From there, I simply decoded the proper base-64 string and subtracted from each character in the decoded string its corresponding character in the "flarebearstare" string to get the flag.

```python
#!/usr/bin/python

x = [0xb9,0xdc,0x92,0xd5,0xde,0xc1,0x9c,0xc0,0xde,0xd4,0xed,0xc6,0xe4,0xc4,0xb5,0xbf,0xaa,0xd1,0xc9,0xcb,0xd5,0xa1,0xd8,0xdf,0xd5,0xd3,0xd7,0x92,0xd5,0xda,0x8f,0xd5,0xd4,0xcf]
y = "flarebearstare"*5

solution=[]

for i in range(0,34):
	solution.append(chr(x[i]-ord(y[i])))

print ''.join(solution)
```



