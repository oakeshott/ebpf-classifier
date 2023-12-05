import os
import subprocess
import time
import argparse
from tqdm import tqdm

curdir = os.path.dirname(__file__)

USERNAME        = 't-hara'
TESTER_IFNAME   = 'enp108s0'
TESTER          = f'{USERNAME}@163.221.216.240'
IFNAME          = 'eno12409'
RESDIR          = f'{curdir}/results'
RSA_PRIVATE_KEY = f'/home/{USERNAME}/.ssh/id_rsa'
TARGET_IP       = '10.0.1.254'
TIME            = 100
ML_NAMES        = ['NN', 'DT', 'RF']

def get_rcvd_pkts():
    cmd = ['pidof', APP_NAME]
    ret = subprocess.run(cmd, capture_output=True, text=True)
    cmd = ['sudo', 'kill', '-SIGUSR1', str(int(ret.stdout))]
    ret = subprocess.run(cmd)
    time.sleep(1)
    ret = int(open("stats.txt", "r").readline())
    return ret

def enable_cpu(max_cpu=24):
    for i in range(1, max_cpu):
        cmd = ['sudo', 'chcpu', '-e', str(i)]
        ret = subprocess.run(cmd)
        # subprocess.run(cmd, stdout=subprocess.DEVNULL,
        #         stderr=subprocess.DEVNULL)
def disable_cpu(n_cpu=24, max_cpu=24):
    for i in range(n_cpu, max_cpu):
        cmd = ['sudo', 'chcpu', '-d', str(i)]
        ret = subprocess.run(cmd)

def xdp_off():
    cmd = ['sudo', 'ip', 'link', 'set', 'dev', IFNAME, 'xdp', 'off']
    subprocess.run(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)

def experiment(pkt_sending_interval, mode, ML_NAME, NUM_THREADS):

    if mode == 'xdp_drv' or mode == 'xdp_skb':
        if ML_NAME == 'filter':
            APP_NAME=f'filter_xdp.py'
        else:
            APP_NAME=f'{ML_NAME}_filter_xdp.py'
    elif mode == 'tc':
        if ML_NAME == 'filter':
            APP_NAME=f'filter_tc.py'
        else:
            APP_NAME=f'{ML_NAME}_filter_tc.py'
    else:
        if ML_NAME == 'filter':
            APP_NAME=f'filter_rawsocket_us.py'
        else:
            APP_NAME=f'{ML_NAME}_filter_rawsocket_us.py'
    LOGDIR = f'{curdir}/results/kernel/{mode}/u{pkt_sending_interval}/{ML_NAME}/{NUM_THREADS}threads'
    os.makedirs(LOGDIR, exist_ok=True)
    print(LOGDIR)
    if ML_NAME == 'filter':
        APP_PATH = f'{curdir}/../filter/{APP_NAME}'
    else:
        APP_PATH = f'{curdir}/../{ML_NAME}-filter/{APP_NAME}'


    cmd = ['sudo', 'killall', APP_NAME]
    subprocess.run(cmd, check=False)
    xdp_off()
    cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'killall', 'hping3']
    subprocess.run(cmd, check=False)
    # cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'killall', 'ping']
    # subprocess.run(cmd, check=False)
    # sudo ethtool -L <interface> combined 1
    cmd = ['sudo', 'ethtool', '-L', IFNAME, 'combined', str(NUM_THREADS)]
    subprocess.run(cmd, check=False)
    # if mode == 'userspace':
    #     cmd = ['sudo', 'ethtool', '-L', IFNAME, 'combined', '1']
        # subprocess.run(cmd, check=False)

    prev_pkts = 0
    list_rxpps = []
    # pkt generation
    time.sleep(1)
    if pkt_sending_interval == 0:
        cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'hping3', TARGET_IP, '-s', '10000', '-p', '10000', '--flood', '-2']
        # cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'hping3', TARGET_IP, '-s', '10000', '-p', '10000', '--flood']
    else:
        cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'hping3', TARGET_IP, '-s', '10000', '-p', '10000', '-i', f'u{pkt_sending_interval}', '-2']
        # cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'hping3', TARGET_IP, '-s', '10000', '-p', '10000', '-i', f'u{pkt_sending_interval}']
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    # cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'ping', TARGET_IP]
    # subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
    #         stderr=subprocess.DEVNULL)

    time.sleep(1)

    cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, f'/home/{USERNAME}/measure-pps.sh', TESTER_IFNAME, str(TIME)]
    # cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, '/home/t-hara/txpps.sh', "/home/t-hara/" + LOGDIR, str(TIME)]
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    if mode == 'xdp_drv':
        cmd = ['sudo', 'PYTHONIOENCODING=utf-8', f'PYTHONPATH=/home/{USERNAME}/.pyenv/versions/3.9.11/lib/python3.9/site-packages:/usr/lib/python3/dist-packages/', f'/home/{USERNAME}/shims/python', APP_PATH, IFNAME, LOGDIR, '-D']
    elif mode == 'xdp_skb':
        cmd = ['sudo', 'PYTHONIOENCODING=utf-8', f'PYTHONPATH=/home/{USERNAME}/.pyenv/versions/3.9.11/lib/python3.9/site-packages:/usr/lib/python3/dist-packages/', f'/home/{USERNAME}/shims/python', APP_PATH, IFNAME, LOGDIR, '-S']
    elif mode == 'tc':
        cmd = ['sudo', 'PYTHONIOENCODING=utf-8', f'PYTHONPATH=/home/{USERNAME}/.pyenv/versions/3.9.11/lib/python3.9/site-packages:/usr/lib/python3/dist-packages/', f'/home/{USERNAME}/shims/python', APP_PATH, IFNAME, LOGDIR]
    else:
        cmd = ['sudo', 'PYTHONIOENCODING=utf-8', f'PYTHONPATH=/home/{USERNAME}/.pyenv/versions/3.9.11/lib/python3.9/site-packages:/usr/lib/python3/dist-packages/', f'/home/{USERNAME}/shims/python', APP_PATH, IFNAME, LOGDIR]
    app = subprocess.Popen(cmd)
    # app = subprocess.Popen(cmd,
    #         stderr=subprocess.DEVNULL)

    cmd = ['mpstat', '-P', 'ALL', '1', str(TIME), '-o', 'JSON']
    print(cmd)
    filename = f'{LOGDIR}/mpstat.json'
    with open(filename, 'w') as f:
        subprocess.run(cmd, stdout=f)

    # time.sleep(140)
    # cleanup
    # cmd = ['sudo', 'killall', APP_NAME]
    # subprocess.run(cmd, check=True)
    xdp_off()
    time.sleep(5)

    cmd = ['ssh', '-t', '-i', RSA_PRIVATE_KEY, TESTER, 'sudo', 'killall', 'hping3']
    subprocess.run(cmd, check=False)

    filename = f'{LOGDIR}/txpps.log'
    txpps, _ = sp.communicate()
    txpps = txpps.decode()
    with open(filename, "w") as f:
        for l in txpps:
            f.write(f"{l}")
    cmd = ['sudo', 'ethtool', '-L', IFNAME, 'combined', '24']
    subprocess.run(cmd, check=False)


def main():
    list_pkt_sending_interval = range(0, 11)
    # list_pkt_sending_interval = [0]
    # modes = ['af_xdp', 'af_xdp-poll', 'af_xdp-bp', 'xdp']
    modes = ['xdp_drv', 'xdp_skb', 'tc', 'userspace']
    # ML_NAMES = ['nn']
    ML_NAMES = ['dt', 'rf', 'filter']
    ML_NAMES = ['nn']
    # ML_NAMES = ['dt', 'filter']
    # NUM_THREADS = range(1, 5)
    NUM_THREADS = [1, 4]
    # NUM_THREADS = [1]
    for NUM_THREAD in NUM_THREADS:
        enable_cpu()
        disable_cpu(n_cpu=NUM_THREAD)
        for mode in modes:
            for pkt_sending_interval in tqdm(list_pkt_sending_interval):
                    for ML_NAME in ML_NAMES:
                        experiment(pkt_sending_interval, mode, ML_NAME, NUM_THREAD)
                        time.sleep(5)
    enable_cpu()
if __name__ == '__main__':
    main()
