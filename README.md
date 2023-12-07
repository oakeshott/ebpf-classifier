# README
These programs are eBPF, XDP, and AF_XDP based packet processing empowered by lightweight neural network and decision tree.

> [!NOTE]
> The research achievement using this program has already been submitted to a journal and under review. 

## Setup

```bash
git clone git@github.com:oakeshott/mlids.git
git submodule update --init --recursive
```

### AF_XDP

```bash
cd xsknf
make
```


## Execution

### in-kernel

```bash
cd nn_filter
# XDP program
sudo python nn_filter_xdp.py $IFNAME $OUTDIR -D
# -D option: DRV mode
# -S option: SKB mode
# -H option: HW mode
# eBPF TC program
sudo python nn_filter_tc.py $IFNAME $OUTDIR
```

### AF_XDP

```bash
cd xsknf
sudo ./examples/mlids/mlids -i $IFNAME -M COMBINED -w $NUM_THREADS -- -q -m NN
# AF_XDP standard: -M COMBINED
# AF_XDP syscall: -M COMBINED -B
# AF_XDP poll: -M COMBINED -p
# AF_XDP skb: -M COMBINED -S
```


