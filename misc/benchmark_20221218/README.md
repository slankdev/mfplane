## Test

```
de VM1 iperf3 -c 10.255.100.1 -t 5 -P10 -b 100M -J --get-server-output -T t5-P10-b100M | jq . > t5_P10_b100M.json
```
