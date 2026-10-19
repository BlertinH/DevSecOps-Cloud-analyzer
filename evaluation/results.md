| Scenario | Expected | Found | Gate (expected) | Gate (found) |
|---|---|---|---|---|
| demo-insecure | 5 | 5 | BLOCK | BLOCK |
| demo-secure | 0 | 0 | PASS | PASS |
| routing | 3 | 3 | BLOCK | BLOCK |
| public-ip | 4 | 4 | BLOCK | BLOCK |
| database | 10 | 10 | BLOCK | BLOCK |
| sg-rules | 4 | 4 | BLOCK | BLOCK |
| iam | 2 | 2 | PASS | PASS |

| Rule | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| NET-01 | 13 | 0 | 0 | 1.00 | 1.00 |
| NET-02 | 1 | 0 | 0 | 1.00 | 1.00 |
| PATH-01 | 6 | 0 | 0 | 1.00 | 1.00 |
| CFG-01 | 5 | 0 | 0 | 1.00 | 1.00 |
| CFG-02 | 3 | 0 | 0 | 1.00 | 1.00 |
