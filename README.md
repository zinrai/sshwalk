# sshwalk

Try a list of SSH credentials against one host in order, stop at the first
that authenticates, and run a command. The result is written as a single
JSON Lines record to stdout.

sshwalk is not a password cracker. It walks a short, operator-supplied list
of known credentials, not a wordlist, and it paces attempts to avoid tripping
account lockout on the target.

Use it only against hosts you are authorized to access.

## Scope

sshwalk handles one host per invocation. It does not read a host list or
manage concurrency. Drive a fleet with a shell loop and collect the output
with a redirect:

```
for h in $(cat hosts); do
  sshwalk --cred-file creds.txt --host "$h" --command 'uname -r'
done > results.jsonl
```

Each line in `hosts` includes the port, for example `192.0.2.10:22`.

## Credentials

Credentials are read from a file, one per line, in the form:

```
user:password
```

The line is split on the first colon, so a password may contain colons. Blank
lines and lines beginning with `#` are ignored.

Example `creds.txt`:

```
# tried in order, top to bottom
root:hunter2
root:s3cr3t-old
ubuntu:ubuntu-pw
```

## Host

The host is given with `--host` and must include the port as `host:port`.
There is no default port. IPv6 addresses are bracketed.

```
sshwalk --cred-file creds.txt --host 192.0.2.10:22 --command 'uname -r'
sshwalk --cred-file creds.txt --host 192.0.2.11:2222 --command 'uname -r'
sshwalk --cred-file creds.txt --host server.example.internal:22 --command 'uname -r'
sshwalk --cred-file creds.txt --host '[2001:db8::1]:22' --command 'uname -r'
```

## Usage

Run a command against one host:

```
sshwalk --cred-file creds.txt --host 192.0.2.10:22 --command 'uname -r'
```

`--command` defaults to `hostname`, so a host can be probed for reachability
and a working credential without naming a command:

```
sshwalk --cred-file creds.txt --host 192.0.2.10:22
```

## Output

sshwalk writes one JSON object per host to stdout, and a one-line status to
stderr so a loop stays readable. The three outcomes are distinguishable:

- `connected: false`. Unreachable (network or port).
- `connected: true, authenticated: false`. Host up, no credential worked
  (manual follow-up).
- `connected: true, authenticated: true`. Logged in. `exit_code`, `stdout`,
  `stderr` are valid.

On success, `auth_user` and `auth_index` name the credential that worked.
`auth_index` is its 1-based position in the credential file, so a specific
password is identified without the password appearing in the output.

## Lockout

Trying several failed logins in a row can trip fail2ban or PAM account
lockout on the target and lock out its legitimate operators. To reduce that
risk, sshwalk pauses one second between attempts on a host. Keep the
credential list short. This guard protects the target's real users, not the
tool.

## Flags

```
--cred-file        credentials to try, one per line: user:password (required)
--host             target host as host:port (required)
--command          command to run on the host (default hostname)
--connect-timeout  TCP connect and SSH handshake timeout (default 10s)
--command-timeout  timeout for the remote command (default 60s)
--version          print version and exit
```

The per-attempt delay (1s) is fixed. It is a lockout guard that protects the
target's legitimate operators, so it is not exposed as a flag. Change it in
`ssh.go` if you must.

## Exit status

- `0`. The host authenticated and the command ran.
- `1`. Usage or input error (missing flag, host given without a port,
  unreadable credential file).
- `2`. The host was unreachable or every credential failed.

In a shell loop, a non-zero exit marks the hosts that need manual attention.

## Host keys

sshwalk does not verify host keys. It is built for bulk sweeps across an
internal fleet where key pinning is impractical, so a changed or unknown host
key will not stop a connection. Do not use it across untrusted networks where
a man-in-the-middle is a concern.

## Security notes

Output contains hostnames, usernames, and which credential worked, which is
useful reconnaissance if it leaks. Treat the results accordingly. The
password values themselves are never written to output.

## License

This project is licensed under the [MIT License](LICENSE).
