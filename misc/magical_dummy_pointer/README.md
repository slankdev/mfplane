# Magical Dummy pointer....

compiler version

``` 
root@L1:~# clang --version
clang version 10.0.0 (https://github.com/llvm/llvm-project.git f5ae66a41b809db97c4fc34b29bb76be3a86fbe9)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /usr/local/bin
``` 

compiler flags
```
			// build with some special parameter
			// TODO(slankdev): cflags += " -nostdinc" for less dependency
			cflags := "-target bpf -O3 -g -I /usr/include/x86_64-linux-gnu"
			cflags += " -D NAME=" + clioptName
			if clioptDebug {
				cflags += " -DDEBUG"
			}
			if _, err := util.LocalExecutef(
				"clang %s -c %s/code/%s -o %s/bin/out.o",
				cflags, tmppath, file, tmppath); err != nil {
				return err
			}
```

- with dummy-ptr:
	- 16-bytes x1-times data copy
- without dummy-ptr
	- 16-bytes x3-times data copy

We are suspecting compiler optimization...?
