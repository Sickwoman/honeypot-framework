# Summary

<!-- What changes and why. Link the issue if there is one. -->

## Test plan

<!-- What you actually ran, not what you intend to run. Delete rows that
     don't apply; don't tick a box you haven't executed. -->

- [ ] `pytest` passes
- [ ] `ruff check .` clean
- [ ] `npm test && npm run build` (if `frontend/` changed)
- [ ] `docker compose up --build` starts and `/health` answers (if the
      Compose stack, a Dockerfile, or `requirements.txt` changed)
- [ ] Manually exercised the change end to end — describe how:

## Security checklist

<!-- This repo handles attacker-controlled input by design. Confirm the
     ones that apply. -->

- [ ] No secrets, tokens, or real IPs in the diff (including test fixtures)
- [ ] Any new subprocess call uses an argument list, never `shell=True`
- [ ] Any attacker-controlled value rendered in the dashboard passes
      through `esc()`
- [ ] Any new file path derived from user or alert data is sanitized
- [ ] New env vars are documented in `.env.example` with no working default
      for anything secret

## Notes for the reviewer

<!-- Anything deliberately left out of scope, known limitations, or parts
     you want a second opinion on. Say so plainly rather than leaving it
     to be discovered. -->
