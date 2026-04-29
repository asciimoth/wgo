# WireGuard Performance Report

- Generated: 2026-04-29 10:57:41Z
- Duration per iperf run: 10s
- Omit window: 1s
- MTU: 1420


## wgo

- Revision: `06c0363`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7643.08 | 7643.51 | 0 | 9553838080 | 9557183616 |
| peer-b -> peer-a | 10.00 | 7720.47 | 7719.98 | 0 | 9650831360 | 9654568744 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.20 | 7435.95 | 0.011 | 92.173 | 9294930720 | 6794540 | 6262762 |
| peer-b -> peer-a | 10.21 | 7598.73 | 0.012 | 92.895 | 9498407040 | 6943280 | 6449950 |


## wireguard-go

- Upstream revision: `f333402bd9cb`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7575.93 | 7575.98 | 0 | 9469952000 | 9474213336 |
| peer-b -> peer-a | 10.00 | 7641.01 | 7640.70 | 0 | 9551216640 | 9554234800 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.21 | 7561.25 | 0.011 | 92.886 | 9451539360 | 6909020 | 6417501 |
| peer-b -> peer-a | 10.21 | 6894.42 | 0.013 | 93.026 | 8618016960 | 6299720 | 5860383 |


## kernel

- Kernel release: `7.0.1`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 1466.57 | 1466.37 | 0 | 1833207552 | 1833274584 |
| peer-b -> peer-a | 10.00 | 1423.83 | 1423.13 | 0 | 1779777576 | 1779271416 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 1745.33 | 0.005 | 0.000 | 2181659040 | 1594780 | 5 |
| peer-b -> peer-a | 10.00 | 1748.43 | 0.006 | 0.000 | 2185544160 | 1597620 | 0 |

