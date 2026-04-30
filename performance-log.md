# WireGuard Performance Report

- Generated: 2026-04-30 14:57:16Z
- Duration per iperf run: 10s
- Omit window: 1s
- MTU: 1420


## wgo

- Revision: `58e79eb`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7838.12 | 7838.22 | 0 | 9797632000 | 9800976088 |
| peer-b -> peer-a | 10.00 | 7588.47 | 7587.91 | 0 | 9485680640 | 9488957608 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.20 | 7086.59 | 0.012 | 94.083 | 8858224080 | 6475310 | 6092147 |
| peer-b -> peer-a | 10.01 | 7113.42 | 0.013 | 94.668 | 8891767440 | 6499830 | 6153234 |


## wireguard-go

- Upstream revision: `f333402bd9cb`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7876.95 | 7877.54 | 0 | 9846128640 | 9849997008 |
| peer-b -> peer-a | 10.00 | 7773.11 | 7772.54 | 0 | 9716367360 | 9719579008 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.21 | 7523.09 | 0.012 | 93.020 | 9403850880 | 6874160 | 6394349 |
| peer-b -> peer-a | 10.21 | 6989.65 | 0.013 | 93.521 | 8737046640 | 6386730 | 5972915 |


## kernel

- Kernel release: `7.0.1`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 1746.39 | 1746.15 | 0 | 2182977792 | 2183139216 |
| peer-b -> peer-a | 10.00 | 1850.03 | 1849.72 | 0 | 2312534232 | 2312513712 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 2037.48 | 0.003 | 0.002 | 2546846640 | 1861730 | 35 |
| peer-b -> peer-a | 10.00 | 2156.01 | 0.004 | 0.008 | 2695014720 | 1970040 | 149 |

