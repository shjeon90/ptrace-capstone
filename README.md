# ptrace-capstone
This is a sample code for ptrace dbg with capstone lib. I just wrote the code for my research, but fill free to use it!
Note that the code is assumed to take a 32-bit binary compied with `-no-pie` option.
Currently, this code was very poorly implemented, so I'll refactor it someday (maybe) ~:P

# Usages
```
$ sudo apt-get install libcapstone-dev
$ make
$ ./bb-counter ./test
```
