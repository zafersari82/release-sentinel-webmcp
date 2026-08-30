# Public adversarial challenge architecture

```text
researcher attack.py
        |
        | arbitrary code
        v
+----------------------------------+
| disposable challenge runtime     |
| no secrets / no network          |
| read-only / no capabilities      |
| resource + wall-clock limits     |
+----------------------------------+
        |
        | JSON only
        v
protocol validation + detachment
        |
        | hostile advisory data
        v
Release Sentinel application plane
        |
        | cannot sign evidence
        v
sealed authoritative evidence
        |
        v
Go Gatekeeper
        |
        v
machine-readable challenge receipt

agent compromised?       expected / measured
authority changed?       BREAKER_WON
```

The challenge worker is not part of the release trust kernel. The important
architectural property is therefore not that the worker is impossible to
compromise; it is that compromising it should still leave no path to evidence
signing or deterministic decision authority.

For public hosting, place each arbitrary-code submission in a fresh disposable
VM/microVM or equivalent hardened isolation domain with no credentials and no
route to production services. The included Docker runner is for reproducible
local/community evaluation and defense-in-depth only.
