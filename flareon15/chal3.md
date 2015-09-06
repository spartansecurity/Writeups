#Challenge 3
####Binary: elfie
####Type: PE Executable
####Arch: x86

##Armen's Solution
This program displays a window with a graphic in a text box.
<br><img src="imgs/chal3-Elfie.jpg" width="500"></br>

Typing into it and pressing "enter" seems to do nothing.  We guess that a certain input is required to obtain the next email.

Searching through the strings reveals text that indicates use of the Python runtime.  Taking a guess that the managed code will copy the key string (with the text "@flare-on.com") somewhere in memory where the user has no control, we assume that taking a memory dump and searching through its strings will reveal the email to the next challenge.

Doing this after opening the program does nothing.  However, after entering some text and trying again, the email is easily found in the next process dump.  Apparently some string-reversal was used for obfuscation, but when the string was reconstructed for verification with the user's input, the plaintext email was left in memory as an artifact.
<br><img src="imgs/chal3-Solved.jpg" width="500"></br>

Why look at the code when you can have the email for free? :)

##Josh's Solution
I can't believe a wrote a shitty script for this.
```python
#!/usr/bin/python
import subprocess
import os
import base64

target=['OOO0OOOOOOOO0000O000O00O0OOOO00O',
        'O0O00OO0OO00OO00OO00O000OOO0O000',
        'O00OO0000OO0OO0OOO00O00000OO0OO0',
        'O00OO00000O0OOO0OO0O0O0OO0OOO0O0',
        'O0O00OO0O0O0O00OOO0OOOOOO00OO0O0',
        'O0OO00O0000OOOO00OOO0OO0000O0OO0',
        'O0O0OO000OOO00000OO0OOOO0OO00000',
        'OO0OOO0O00000O00OOOOO0OO0OO00OOO',
        'O000000000OOO00OO00000OOOO00OOOO',
        'OOO0OOO00O0OO0O0OOOO00OO00OO0O00',
        'O0OO0OOO00O0OOO0O00OOO0O0OOOO00O',
        'OOOO000O0OOOOO0O0O0000O0O0OO00O0',
        'O00O0O00OO0O0OO00O0OO0O00O0O00OO',
        'OOOOOOO0O0O00OOO0OO00O0O00OOOOO0',
        'O00O000O0O00000O00OO0OO0OOO000O0',
        'O0O000O0O0O0OO0000O0O0OOO0OOOOO0',
        'O000000OOO0O00OO00OO00OO0OO00O0O',
        'OOOOOO000OOO0O000O0O00OO0OOOO0O0',
        'O00OOOO0OO0O000OO0OOOOO0OOOO0000',
        'O0OO00000OOOOO0OOO000O00000OOO00',
        'OOO00O0OOOOO00OO0OOOOO0O0O00O0O0',
        'OOO000O0OOO0OOO0OOOO0OOOOO0O0O00',
        'OO0OOOO0O00OOOO0OOOO0O0OOO0OO0O0',
        'O0OO0OO00000OOOO0OOOOO0O00O0O0O0',
        'OO00OOO00OO0OOO000O000000O0O0000',
        'OO0O0000OO0000OO000OO0O0OO0O00OO',
        'OO00000O0OO000O0O000OOOOOOO0O0OO',
        'O0O00O000OOOO000O0OOOOO0O000000O',
        'O000OOOOOOOOOO0O0OO0OO000OO000O0',
        'O0OO00OOO0O0OOOO0O0O0000000O0OOO',
        'O0000O0OOOO00OO0OOO00OO000O0000O',
        'OOOOO0OO0O00OOOOOO00O00000O0OO0O',
        'OO0O0OOOO0O000OOOO00O0O00O0O0O0O',
        'O0OOO00OOOO0OO0OO0O000O0OO0OO000',
        'O0OOOO0O00OOOOO0OOO000O00O00OO00',
        'OO0OO00000O00O0000000O00O0OO0O00',
        'OOO0000OO00000OO00O0OO0000OOOO00',
        'O00O000O00O0O00OO0OO0O000000OOOO',
        'O000O00O000O00O000O0OO00O0000O0O',
        'O0O0OO0OO0O0OOO0O0OOO00O0OOOOO00',
        'O0OOO0OO00OO0OOO00OO0O0O0O0O00OO',
        'OO0OOO00000OO000O0OOOO00O0O0O00O',
        'O00OO00OOO0OOOO0OOOO0OO00000OOO0',
        'OOOOOO0OO0O0OO0O0000OOO0O00O0O0O',
        'O0O0O00O0000O00OOOO000O00OO00O00',
        'OOOOO0000OO000O0O0000OOOOO0000OO',
        'OO00OOO0O00OO0OO0OOOO000OO0000OO',
        'O00000O0OO00O0OO00000O000OOO00O0',
        'O0OOO00O0O0O0OO00000OO0OO00O00OO',
        'O0000OO00000000OO000O0OOO000OO00',
        'OO0OO0O00000O0O000OOO0O0O0O000O0',
        'OOOOO0O00OOOOO0O0OOOOOOO0OO0OO00',
        'OOOOO00O0O0O0O0O0OO00O0OOOO00O0O',
        'O0OOOO0OO000OOOOOO0O0OO0OOO0O000',
        'OOOO000OOOOO00000O000OO0O00O0O0O',
        'O00OOO000O0O0OOOO00O0O00O0OO00OO',
        'OO0O00OO0OO00O0O000O0000O0OOOOO0',
        'OO0O0O00OO00OOOOOO0O0O0OOO0OOO0O',
        'OO0OOO00OOO00OOOOOOOOOOOO00OO00O',
        'OOO0000O0OO0OOOOO000O00O0OO0O00O',
        'OOO0O00O00OOOOOOO00OOOO0000O0O00',
        'O0O00OO00O0O00O0O00O0OOO00O0O0OO',
        'O00OOOOO000O00O0O00000OOO0000OOO',
        'O0O0OOO000O000OO0O0O0OOOOO0OO000']

def getchunk(chunk):
  decodeme=""
  p = subprocess.Popen('cat elfie | grep '+chunk, stdout=subprocess.PIPE,shell=True)
  out = p.communicate()
  for i in out[0].split(os.linesep):
    try:
      decodeme+=i.split("'")[1]
    except:
      return decodeme
def pad(chunk):
  missingpadding= 4 - len(chunk) % 4
  print missingpadding
  chunk+=b'='*missingpadding
  return chunk

chunk = ""
for i in target:
  chunk += getchunk(i)
print pad(chunk).decode('base64')
```

```
jwang@avantgarde:~/Documents/flareon15/elfie$ python elfie.py | grep @
        if (O0O0O0000OOO000O00000OOO000OO000 == ''.join((OO00O00OOOO00OO000O00OO0OOOO0000 for OO00O00OOOO00OO000O00OO0OOOO0000 in reversed('moc.no-eralf@OOOOY.sev0000L.eiflE')))):
```
