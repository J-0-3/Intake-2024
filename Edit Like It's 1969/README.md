# Summary

The key to this challenge was identifying that the software running on the
remote was `ed`, the original UNIX text editor. The name "Edit Like It's 1969"
is a pointer to the fact that ed was developed in 1969, and the description
"The experienced user will know what is wrong" is a reference to a historical
joke in the glibc documentation about the obtuse and unhelpful nature of `ed`
error codes (a single '?').

# Part 0

In part 0, the editor is completely unrestricted, and allows for the execution
of shell commands with the `!` character (which could be found in the `ed`
documentation or GTFObins). Entering `!/bin/sh` will spawn a shell, and a note
in the current directory will point to the location of the flag.

![](/Assets/Pasted%20image%2020241003182551.png)

# Part 1

In part 1, the shell is disabled (it is completely deleted from the system). As
such, you will have to figure out how to use `ed` to read and display a file. 

To read the file you can run `r /etc/txt.flag`. This will read the flag into
ed's buffer, which can be displayed with `,p`.

![](/Assets/Pasted%20image%2020241003183341.png)

# Part 2

In part 2, `ed` is run in restricted mode, which the documentation specifies as
preventing both executing shell commands and reading/writing files outside of
the current directory. However, a helpful message tells you that a script
called `system_info.sh` has been executed from the current directory when you
connect to the system. 

You can overwrite this file by entering `i` to enter insert mode, entering a
shebang `#!/bin/sh`, and then a new line followed by your payload (e.g.
`/bin/sh` or `cat /etc/flag.txt`), then a `.` on a new line to finish editing,
and `w system_info.sh` to write the contents of the buffer to `system_info.sh`.
Upon connecting the next time, you will get your shell.

![](/Assets/Pasted%20image%2020241003185256.png)

