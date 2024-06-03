# XDP Block
- Block a domain with static DNS A records

## Compile bpf file
```bash
clang -O2 -g -Wall -target bpf -c xdp_block.c -o xdp_block.o
```

## Compile loader file
```bash
clang -O2 -g -Wall xdp_loader.c -o xdp_loader.out -lbpf -lxdp
```

## Execute loader file
```bash
sudo ./xdp_loader.out google.com
```

## Open a website
```bash
curl https://www.google.com
```
