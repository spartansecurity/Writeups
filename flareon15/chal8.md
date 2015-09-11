#Challenge 8
####Binary: 
####Type: PE Executable
####Arch: x86
##Josh's Solution

When the binary is run it simply prints `the one who seeks finds...` When we run strings on it, we can see base-64 encoded data.

When this data is base-64 decoded, it produces a valid .PNG file.

<img src="imgs/chal8-gdssagh.png" width="500"></br>

Using `zsteg`
