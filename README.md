# stt
This is a extended version of [guile](https://www.gnu.org/software/guile/) to add basic support for
handling arbitrary SCTP packets.

## Supported Platforms
It runs on Unix operating systems not providing kernel SCTP support:
* FreeBSD, when compiling a kernel without the SCTP option.
* Linux, without having the `sctp`module loaded.
* Mac OS X
