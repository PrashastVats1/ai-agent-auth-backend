# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Set up

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

See the [README](README.md) for the Neon and MonoCloud setup needed to run the app itself. You don't need either to run the tests.

## Run the tests

The tests run against a real PostgreSQL, because the app uses Postgres `ARRAY`, `UUID` and `UPDATE … RETURNING`. Point `TEST_DATABASE_URL` at any Postgres you can create schemas in:

```bash
export TEST_DATABASE_URL=postgresql://user:password@localhost:5432/scratch
pytest
```

Each run creates a throwaway schema, applies `schema.sql` to it, and drops it afterwards. Every test runs inside that schema, so nothing in your other tables is read or changed. A scratch database is still the safest choice, and a second free Neon project works well.

If you point it at the same database as your app (the `NEON_DATABASE_URL` in your `.env`), the tests stop with an error until you confirm with `ALLOW_TEST_ON_REAL_DB=1`. If a run is killed part-way, an empty `test_<hex>` schema can be left behind; drop it with `DROP SCHEMA test_<hex> CASCADE;`.

Without `TEST_DATABASE_URL` the database tests are skipped and only the pure unit tests run. MonoCloud is never contacted: the tests sign real RS256 tokens with a throwaway key.

## Rules the code depends on

These are easy to break by accident, so please keep them:

- **Two JWT families, two validators.** `validate_monocloud_jwt()` for MonoCloud tokens and `validate_agent_jwt()` for our delegation JWTs. Never validate one kind with the other.
- **User identity comes from the validated token**, never from a request body.
- **Delegation JWTs live at most 30 minutes.**
- **Polling is every 4 seconds, not faster.** Neon's free tier has a small connection limit.
- **Don't raise the connection pool** (`pool_size=5`, `max_overflow=2`).
- **Datetimes are timezone-aware** (`datetime.now(timezone.utc)`), never `utcnow()`.
- Every environment variable belongs in `.env.example`.

## Pull requests

- Add or update tests for behaviour changes. Security checks (ownership, consent, policy) need a test that fails when the check is removed.
- Keep a PR to one topic.
- If you change the database schema, put the migration at the bottom of `schema.sql` and say so in the PR description, since it has to run before the new code deploys.

To report a security problem, please don't open an issue. See [SECURITY.md](SECURITY.md).
