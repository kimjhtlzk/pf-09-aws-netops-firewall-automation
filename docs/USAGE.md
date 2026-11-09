# Usage

The everyday order is: sign in, check, apply, verify.

## 1. Sign in

```bash
netops sso-login --role <permission-set>
```

Approve in the browser. The command writes temporary credentials to `~/.aws/credentials` and renews them before they expire, as long as it keeps running.

## 2. Check whether work is needed

Fill in `workspace/FW_RT_Confirm.xlsx`. Running the command once creates an empty form.

| Column | Example |
|---|---|
| Source | `10.0.1.10`, `10.0.1.0/24`, `10.0.1.10-10.0.1.20` |
| Destination | The same formats, or an RDS address |
| Port | `443`, `8000-8100`, `any` |
| Protocol | `tcp`, `udp`, `icmp`, `any` |

```bash
netops confirm
```

Flows that are already open need no work. Blocked flows go to `workspace/modify_from_confirm/FW_Modify.xlsx`.

## 3. Preview and apply

```bash
netops modify --file workspace/modify_from_confirm/FW_Modify.xlsx
```

This only prints the plan: the security group, the new rules, and which resources are affected. Nothing changes.

```bash
netops modify --file workspace/modify_from_confirm/FW_Modify.xlsx --apply
```

You must type `apply` to continue.

## 4. Verify real traffic

```bash
netops flowlog --account svc-a-dev --vpc vpc-00000000 --table example_flow_logs --address 10.0.1.10 --interval 1h
```

## Inventory

```bash
netops collect
netops collect --kind sg --kind route_table
```

Files are named `aws_ec2_inventory_YYYYMMDD.xlsx`. Change the first word with `output_prefix`.

## Offline install

```bash
pip download . -d wheels                 # on a connected machine
pip install --no-index --find-links wheels aws-netops-firewall-automation   # on the isolated machine
```
