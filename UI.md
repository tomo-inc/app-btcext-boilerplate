# UI Confirmation click count

Current

| Action            | Action Confirm | FP Confirm | Cov Confirm | Message | Timelock | Output | Fee | Final Confirm | Total |
|-------------------|----------------|------------|-------------|---------|----------|--------|-----|---------------|-------|
| Slashing          | 2+1            | 2+1        |  7+1        |         |          |    2   |   1 |       1       |   18  |  
| Unbonding Slashing| 2+1            | 2+1        |  7+1        |         |          |    2   |   1 |       1       |   18  |
| Pop Sign          | 2+1            | 0          |    0        | 1       |          | 1      |  1  |       1       |   7   |
| Staking           | 2+1            | 2+1        |  7+1        |         |   2+1    |   2    |   1 |         1     |   21  |
| Unbonding         | 2+1            | 0          |  7+1        |         |          |        |     |               |   18  |
| Withdraw          | 2+1            | 0          |    0        |         |          |   2    |   1 |        1      |   7   |
| Expansion         | 2+1            | 2+1        |  7+1        |         |   2+1    |   2    |   1 |        1      |   21  |

The staking process needs 64 clicks


If only display all infomation when staking
| Action            | Action Confirm | FP Confirm | Cov Confirm | Message | Timelock | Output | Fee | Final Confirm | Total | Saving |
|-------------------|----------------|------------|-------------|---------|----------|--------|-----|---------------|-------|--------|
| Slashing          | 2+1            |            |             |         |          |    2   |   1 |       1       |   7   |  61%   |
| Unbonding Slashing| 2+1            |            |             |         |          |    2   |   1 |       1       |   7   |  61%   |
| Pop Sign          | 2+1            | 0          |    0        | 1       |          | 1      |  1  |       1       |   7   |        |
| Staking           | 2+1            | 2+1        |  7+1        |         |   2+1    |   2    |   1 |         1     |   21  |        |
| Unbonding         | 2+1            | 0          |  7+1        |         |          |        |     |               |   18  |        |
| Withdraw          | 2+1            | 0          |    0        |         |          |   2    |   1 |        1      |   7   |        |
| Expansion         | 2+1            | 2+1        |  7+1        |         |   2+1    |   2    |   1 |        1      |   21  |        |

The staking process needs 42 clicks

If we decide not to display cov confirm but keep FP confirm -- bottom line
| Action            | Action Confirm | FP Confirm | Cov Confirm | Message | Timelock | Output | Fee | Final Confirm | Total | Saving |
|-------------------|----------------|------------|-------------|---------|----------|--------|-----|---------------|-------|--------|
| Slashing          | 2+1            |            |             |         |          |    2   |   1 |       1       |   7   |  61%   |
| Unbonding Slashing| 2+1            |            |             |         |          |    2   |   1 |       1       |   7   |  61%   |
| Pop Sign          | 2+1            | 0          |    0        | 1       |          | 1      |  1  |       1       |   7   |        |
| Staking           | 2+1            | 2+1        |             |         |   2+1    |   2    |   1 |         1     |   13  |  38%   |
| Unbonding         | 2+1            | 0          |             |         |          |        |     |               |   10  |  44%   |
| Withdraw          | 2+1            | 0          |    0        |         |          |   2    |   1 |        1      |   7   |        |
| Expansion         | 2+1            | 2+1        |             |         |   2+1    |   2    |   1 |        1      |   13  |  38%   |

The staking process needs 34 clicks