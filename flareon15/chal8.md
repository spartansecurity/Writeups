#Challenge 8
####Binary: 
####Type: PE Executable
####Arch: x86
##Josh's Solution

When the binary is run it simply prints `the one who seeks finds...`. When we run strings on the binary, we can see base-64 encoded data.

Base-64 decoding this data produces a valid .PNG file.

<img src="imgs/chal8-gdssagh.png" width="500"></br>

Using `zsteg`
