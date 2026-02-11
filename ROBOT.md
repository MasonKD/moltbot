# ROBOT Notes

- If `clawdctl.py` adds, removes, or changes any AWS API/CLI operations, update `clawd-cli-aws-policy.json` in the same change.
- Keep the policy least-privilege: only actions needed by current tool behavior.
- Keep mutating paths parallel-safe. Do not remove `mutation_lock()` protection around launch/terminate flows, and apply the lock to any new mutating AWS operations.
