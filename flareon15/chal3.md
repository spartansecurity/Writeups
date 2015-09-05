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
