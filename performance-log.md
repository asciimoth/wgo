# WireGuard Performance Report

- Generated: 2026-04-30 17:03:35Z
- Duration per iperf run: 10s
- Omit window: 1s
- MTU: 1420


## wgo

- Revision: `184ad93`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7748.99 | 7749.32 | 0 | 9686220800 | 9689628664 |
| peer-b -> peer-a | 10.00 | 7635.91 | 7636.63 | 0 | 9544663040 | 9548793392 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.20 | 7105.21 | 0.015 | 93.504 | 8881507440 | 6492330 | 6070614 |
| peer-b -> peer-a | 10.02 | 7121.29 | 0.013 | 93.997 | 8901603360 | 6507020 | 6116428 |


## wgo-amnezia

- Revision: `184ad93`
- Profile: non-default Amnezia UAPI fields (, , , , , , )

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 2.95 | 2.92 | 354 | 3681288 | 3645720 |
| peer-b -> peer-a | 10.00 | 6.63 | 6.61 | 388 | 8281872 | 8259984 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.21 | 7817.26 | 0.014 | 96.371 | 9771555600 | 7142950 | 6883712 |
| peer-b -> peer-a | 10.20 | 7710.57 | 0.014 | 94.983 | 9638189280 | 7045460 | 6691991 |


## wireguard-go

- Upstream revision: `f333402bd9cb`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 7742.56 | 7741.85 | 0 | 9678356480 | 9681239808 |
| peer-b -> peer-a | 10.00 | 7715.43 | 7715.16 | 0 | 9644277760 | 9647686568 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.20 | 7268.00 | 0.009 | 93.915 | 9084983760 | 6641070 | 6236942 |
| peer-b -> peer-a | 10.20 | 7458.99 | 0.012 | 93.428 | 9323740800 | 6815600 | 6367700 |


## amneziawg-go

- Upstream revision: `12a012205e3c`
- Profile: non-default Amnezia UAPI fields (, , , , , , )

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 4.21 | 4.17 | 366 | 5264064 | 5218920 |
| peer-b -> peer-a | 10.00 | 4.78 | 4.76 | 356 | 5974056 | 5952168 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.02 | 7411.04 | 0.014 | 96.562 | 9263781360 | 6771770 | 6538952 |
| peer-b -> peer-a | 10.21 | 7796.34 | 0.011 | 96.018 | 9745413120 | 7123840 | 6840198 |


## kernel

- Kernel release: `7.0.1`

### TCP

| Direction | Duration (s) | Sender (Mbps) | Receiver (Mbps) | Retransmits | Bytes Sent | Bytes Received |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 1697.26 | 1696.51 | 0 | 2121575112 | 2121011496 |
| peer-b -> peer-a | 10.00 | 1683.17 | 1683.25 | 0 | 2103958008 | 2104802064 |

### UDP

| Direction | Duration (s) | Throughput (Mbps) | Jitter (ms) | Lost (%) | Bytes | Packets | Lost Packets |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| peer-a -> peer-b | 10.00 | 2092.58 | 0.004 | 0.013 | 2615711760 | 1912070 | 245 |
| peer-b -> peer-a | 10.00 | 2192.93 | 0.005 | 0.001 | 2741157360 | 2003770 | 13 |

