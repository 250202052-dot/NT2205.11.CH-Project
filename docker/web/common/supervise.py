"""Each node runs its own service and SSH. Stop process groups cleanly."""
import os
import signal
import subprocess
import sys
import time

services = {
    "frontend": ["/usr/sbin/nginx", "-g", "daemon off;"],
    "backend": ["python3", "/opt/lab/app.py"],
    "db": ["su", "postgres", "-c", "postgres -D /var/lib/postgresql/data -c config_file=/opt/lab/postgresql.conf"],
}
children = []
stopping = False

def signal_groups(sig):
    for child in children:
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass

def stop(signum=None, frame=None):
    global stopping
    stopping = True
    signal_groups(signal.SIGTERM)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
unexpected_exit = False
try:
    for command in (["/usr/sbin/sshd", "-D", "-e"], services[os.environ["NODE_ROLE"]]):
        children.append(subprocess.Popen(command, start_new_session=True))
    while not stopping and all(child.poll() is None for child in children):
        time.sleep(0.2)
    unexpected_exit = not stopping
finally:
    stop()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            signal_groups(signal.SIGKILL)
            child.wait()
sys.exit(1 if unexpected_exit else 0)
