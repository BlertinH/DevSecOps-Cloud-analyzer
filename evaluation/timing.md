CPU: AMD Ryzen 5 5500U with Radeon Graphics
Python 3.14.4

| Scenario | Resources | Time (ms) |
|---|---|---|
| demo-insecure | 31 | 0.8 |
| demo-secure | 30 | 0.5 |
| routing | 37 | 0.6 |
| public-ip | 19 | 0.8 |
| database | 27 | 0.8 |
| sg-rules | 31 | 1.6 |
| iam | 17 | 0.3 |

| Copies of demo-insecure | Resources | Attack graph nodes | Attack graph edges | Attack paths | Findings | Time (s) |
|---|---|---|---|---|---|---|
| 1 | 31 | 4 | 4 | 2 | 5 | 0.00 |
| 10 | 310 | 31 | 40 | 20 | 50 | 0.01 |
| 50 | 1550 | 151 | 200 | 100 | 250 | 0.04 |
| 100 | 3100 | 301 | 400 | 200 | 500 | 0.12 |
| 200 | 6200 | 601 | 800 | 400 | 1000 | 0.50 |
| 500 | 15500 | 1501 | 2000 | 1000 | 2500 | 2.98 |
