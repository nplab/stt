# stt
This is a extended version of [guile](https://www.gnu.org/software/guile/) to add basic support for
handling arbitrary SCTP packets.

## Installation
### Linux (Ubuntu)
For installing the required packages run:
```
sudo apt-get install guile-2.2 guile-2.2-dev
```
Then download the sources, compile them and install the files:
```
wget https://github.com/nplab/stt/releases/download/stt-0.9.9h/stt-0.9.9h.tar.gz
tar xvfz stt-0.9.9h.tar.gz
cd stt-0.9.9h
./configure --prefix=/usr
make
sudo make install
```
### FreeBSD
For installing the required packages run:
```
sudo pkg install wget guile2
```
Then download the sources, compile them and install the files:
```
wget https://github.com/nplab/stt/releases/download/stt-0.9.9h/stt-0.9.9h.tar.gz
tar xvfz stt-0.9.9h.tar.gz
cd stt-0.9.9h
./configure
make
sudo make install
```
Please note that you can only use this tool on FreeBSD if you compiled a kernel without SCTP support.
