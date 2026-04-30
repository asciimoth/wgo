# WireGuard Performance Report

- Generated: 2026-04-30 18:43:37Z
- Duration per iperf run: 10s
- Omit window: 1s
- MTU: 1420


## wgo

- Revision: `61cd91e`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7872.73 | 7873.98 | 0 | 9840885760 | 9844360832 |
| peer-b -> peer-a | 10.00 | 7672.45 | 7672.26 | 0 | 9590538240 | 9594144464 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.21 | 7007.51 | 0.013 | 93.501 | 8759386080 | 6403060 | 5986896 |
| peer-b -> peer-a | 10.21 | 7626.96 | 0.011 | 93.161 | 9533687760 | 6969070 | 6492485 |


## wgo-amnezia

- Revision: `61cd91e`
- Profile: non-default Amnezia UAPI fields (, , , , , , )

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 6.78 | 6.78 | 416 | 8478864 | 8474760 |
| peer-b -> peer-a | 10.00 | 6.81 | 6.78 | 414 | 8511696 | 8478864 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.21 | 7322.59 | 0.015 | 96.691 | 9153219600 | 6690950 | 6469531 |
| peer-b -> peer-a | 10.20 | 7466.25 | 0.014 | 96.922 | 9332810640 | 6822230 | 6612256 |


## wireguard-go

- Upstream revision: `f333402bd9cb`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7736.66 | 7737.30 | 0 | 9670492160 | 9674755120 |
| peer-b -> peer-a | 10.00 | 7787.80 | 7788.41 | 0 | 9734717440 | 9738457136 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.20 | 7045.08 | 0.012 | 93.342 | 8806335840 | 6437380 | 6008770 |
| peer-b -> peer-a | 10.01 | 7068.67 | 0.011 | 94.319 | 8835816240 | 6458930 | 6092023 |


## amneziawg-go

- Upstream revision: `12a012205e3c`
- Profile: non-default Amnezia UAPI fields (, , , , , , )

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 5.96 | 5.96 | 402 | 7447392 | 7444656 |
| peer-b -> peer-a | 10.00 | 6.87 | 6.87 | 412 | 8592408 | 8593776 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.01 | 7995.92 | 0.017 | 95.702 | 9994881600 | 7306200 | 6992151 |
| peer-b -> peer-a | 10.21 | 7267.04 | 0.016 | 96.228 | 9083779920 | 6640190 | 6389691 |


## kernel

- Kernel release: `7.0.1`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 1943.60 | 1943.87 | 0 | 2429488656 | 2430284832 |
| peer-b -> peer-a | 10.00 | 1739.39 | 1738.96 | 0 | 2174233536 | 2174147352 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 2220.14 | 0.005 | 0.046 | 2775165840 | 2028630 | 928 |
| peer-b -> peer-a | 10.00 | 1998.45 | 0.004 | 0.007 | 2498063760 | 1826070 | 136 |

