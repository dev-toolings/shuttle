# Review rules

Review the diff against its goal. Name file and line. Score frequency and
severity from 1 to 10.

## Bugs to look for

- Crash boundaries: a process killed between two mutations must leave a state
  signed recovery can finish. Check each step of stop, rm, create, drop, dump.
- Durable proof first: evidence is journaled before the object it describes
  is destroyed. A failed journal write stops the mutation.
- Refusals: a refusal must not leave a reservation, lock or recovery_required
  behind, and must not lose the evidence of what happened.
- Shared host resources: registry, edge and PostgreSQL are shared by all
  applications. An application-level lock does not protect them.
- Docker names: use `container inspect`, `volume inspect` and so on. Generic
  `docker inspect` falls back to another object of the same name.
- Compatibility: strict decoders mean a new JSON field can break an older CLI
  or helper. Check every response and embedded reader, not only the journal.
- Trust boundary: the helper derives from the signed payload and re-validates.
  Never trust a value the CLI claims.
- Exit codes: a command reports what really happened. Check the observed
  state, not the error text. Go error types do not cross SSH.
- Test doubles: a fake must behave like the real tool. A green test on a
  fake is not proof for Docker, SSH or disk behavior.

## Nits to skip

- Style gofmt already settles.
- Long files or functions, unless the length hides a bug.
- Wording of historical CHANGELOG entries.

## Paths to ignore

- `tmp/`, `dist/`
- Generated output, unless the generator changed.
