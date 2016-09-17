# stt
This is a extended version of [guile](https://www.gnu.org/software/guile/) to add basic support for
handling arbitrary SCTP packets.

## Installation
### Linux (Ubuntu)
For installing the required packages run:
```
sudo apt-get install guile-2.0 guile-2.0-dev
```
Then download the sources, compile them and install the files:
```
wget https://github.com/nplab/stt/releases/download/0.9.9g/stt-0.9.9g.tar.gz
tar xvfz stt-0.9.9g.tar.gz
cd stt-0.9.9g
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
wget https://github.com/nplab/stt/releases/download/0.9.9g/stt-0.9.9g.tar.gz
tar xvfz stt-0.9.9g.tar.gz
cd stt-0.9.9g
./configure
make
sudo make install
```
Please note that you can only use this tool on FreeBSD if you compiled a kernel without SCTP support.
