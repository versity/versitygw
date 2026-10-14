# v1.9.0

## Object Lock default-retention migration
### Important: migrate legacy bucket default retention

We corrected an issue in bucket default Object Lock retention in pull request
[#2479](https://github.com/versity/versitygw/pull/2479). In affected releases,
bucket default retention was not stored on individual objects. Protection was
instead calculated from the live bucket rule. Changing or removing that rule
could therefore unlock existing objects, including objects in `COMPLIANCE`
mode. The old behavior also used a common expiration based on the time the
bucket rule was configured, rather than calculating a separate expiration from
each object's creation time.

The corrected behavior stores bucket default retention on each newly written
object. Later changes to the bucket default-retention rule no longer modify the
retention of objects that already received it.

### Required action

1. Upgrade to v1.9.0 or newer.
2. Reapply the intended bucket default-retention configuration. This protects
 objects written after the configuration is applied; it does not retroactively
 protect existing objects.
3. Assess objects written before the upgrade. If preserving their previous
 effective protection is required, use the migration tool below.
4. Confirm object-level retention with `GetObjectRetention` or `HeadObject`
 before declaring the migration complete.

Do not change or remove the legacy bucket default-retention configuration until
its historical mode, period, and configuration time have been recorded.

### Preserving the legacy effective retention

The migration tool preserves the protection the previous implementation
actually enforced. It does **not** recreate the correct per-object retention
that should have been assigned historically.

For each legacy bucket rule, determine:

- the retention mode (`COMPLIANCE` or `GOVERNANCE`); and
- the historical rule expiration:

  ```text
  legacy retain-until = bucket-rule configured-at time + Days or Years
  ```

The old implementation used this same expiration for every object without
explicit retention. If that time is already past, the old implementation no
longer protected those objects, so the tool makes no changes.

`--legacy-retain-until` is that **single, already-calculated historical rule
expiration**. It is not a retention duration, an object creation-time cutoff,
or a new desired retention date. Every eligible legacy object version receives
the same timestamp because that is how the previous implementation behaved.

For example, if the legacy bucket rule was configured at
`2026-01-01T00:00:00Z` with a `COMPLIANCE` period of one year, pass:

```text
--mode COMPLIANCE --legacy-retain-until 2027-01-01T00:00:00Z
```

The S3 API exposes the current bucket rule but not its historical internal
configuration time. Obtain the legacy rule's `CreatedAt` value, mode, and
Days/Years period from the server-side bucket configuration before replacing
it. Calculate `CreatedAt + period` yourself; do not infer the value from an
updated bucket rule.

### Running the migration tool

[`tools/migrate-object-lock-default-retention.sh`](tools/migrate-object-lock-default-retention.sh)
uses the S3 API through AWS CLI. It requires `aws`, `jq`, and `python3`.
It lists all object versions in versioned buckets, skips delete markers and
objects that already have retention, and stops on unexpected API errors.

Run a dry run first. Replace the mode, calculated legacy expiration, endpoint,
and bucket with values approved for the migration:

```sh
tools/migrate-object-lock-default-retention.sh \
  --bucket records \
  --mode COMPLIANCE \
  --legacy-retain-until 2027-10-08T18:59:27Z \
  --endpoint-url http://127.0.0.1:7070 \
  --report records-retention-dry-run.jsonl
```

Review the JSON Lines report. Only then apply the migration:

```sh
tools/migrate-object-lock-default-retention.sh \
  --bucket records \
  --mode COMPLIANCE \
  --legacy-retain-until 2027-10-08T00:00:00Z \
  --endpoint-url http://127.0.0.1:7070 \
  --report records-retention-applied.jsonl \
  --apply
```

`COMPLIANCE` retention can be irreversible. Run the tool with `--apply` only
after reviewing the dry-run report and confirming the calculated historical
expiration and retention mode.
