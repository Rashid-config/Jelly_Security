# Detection 1.1

Detectors emit signals. The policy engine decides. No detector writes a ban.

| Detector | Subject | Default action |
|---|---|---|
| `single_ip_brute_force` | IP | Alert, or recommended temporary source ban if identity is verified |
| `distributed_account_attack` | Username | Manual review. Never lock the account |
| `password_spray` | IP | Throttle recommendation on a verified source |
| `username_enumeration` | IP | Alert. The plugin does not confirm that a name exists |
| `credential_stuffing_pattern` | IP | Behavioral guess only; passwords are never seen |
| `honeypot_username` | IP | Alert. The decoy name is not stored in events |
| `administrative_account_targeting` | Listed username | Higher sensitivity, no extra lock |

Name-diversity signals are counted once. Untrusted client IP cannot raise a temporary source ban. Webhook failures never affect sign-in.
