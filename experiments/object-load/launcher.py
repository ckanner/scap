#!/usr/bin/env python3
"""Pass this owned process's proc directory, then exec the unchanged daemon."""
import array
import json
import os
from pathlib import Path
import socket
import sys

if __name__ == '__main__':
    descriptor, nonce, *command = sys.argv[1:]
    if not command:
        raise SystemExit('missing executable')
    channel = socket.socket(fileno=int(descriptor))
    proc = os.open('/proc/self', os.O_RDONLY | os.O_DIRECTORY)
    try:
        proof = {'nonce': nonce, 'reported_pid': os.getpid(),
                 'stat': Path('/proc/self/stat').read_text(),
                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'source': 'owned_pre_exec_proc_self_fd'}
        payload = json.dumps(proof, separators=(',', ':')).encode()
        if len(payload) > 8192:
            raise RuntimeError('process proof exceeds bound')
        channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [proc]))])
    finally:
        os.close(proc)
        channel.close()
    os.execve(command[0], command, os.environ)
