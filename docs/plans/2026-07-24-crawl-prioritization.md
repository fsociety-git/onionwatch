# Category-Aware Crawl Prioritization Implementation Plan


**Goal:** Make the crawl frontier priority-ordered so high-value pages (by parent category) are fetched first, opt-in via a config weight map.

**Architecture:** Add a `priority` column to `frontier`; `enqueue` becomes a keep-highest upsert; `next_pending` orders by `priority DESC, depth ASC`. `discover.crawl` derives each child link's priority from the just-computed parent category via a `priority_for` helper reading a new `Config.crawl_priority` weight map. Seeds use the map's `default`. No config → all zero → identical BFS.

**Tech Stack:** Python 3.11+, sqlite3 (ON CONFLICT upsert), tomllib, pytest/pytest-asyncio. Stdlib only.

## Global Constraints

- Python 3.11+; **no new dependencies** (stdlib only).
- **Opt-in / additive:** with no `[crawl_priority]` config, every priority is 0 and crawl order + behavior are byte-identical to today (BFS by depth). This is the headline invariant.
- Migration is additive + idempotent: `frontier` gains `priority INTEGER DEFAULT 0` in both `SCHEMA` (fresh DBs) and the `init_schema` ALTER loop (swallow `sqlite3.OperationalError`), matching the existing `case_id` pattern.
- `enqueue`'s new `priority` parameter defaults to `0`, so every existing caller is behaviorally unchanged.
- Keep-highest semantics: re-enqueue may only *raise* a `pending` row's priority; never lower it, never touch an `in_progress`/`done`/`deferred`/`failed` row.
- `next_pending` ordering is `priority DESC, depth ASC` (priority primary, depth tiebreak).
- Follow existing test style: `Database(str(tmp_path / "t.db"))`, `db.init_schema()`, pytest, `@pytest.mark.asyncio` for crawl tests, `Config(...)` kwargs, `FakeClient`.
- Run the suite with `.venv/bin/python -m pytest` (pytest is not on PATH). Baseline before this plan: **215 passed, 1 deselected**.

---

## File Structure

- `src/onionwatch/db.py` (modify) — `SCHEMA` frontier block (add `priority`); `init_schema` ALTER loop (one line); `enqueue` (upsert + `priority` param); `next_pending` (ORDER BY).
- `src/onionwatch/config.py` (modify) — `Config.crawl_priority` field; `priority_for(category, weights)` helper.
- `src/onionwatch/discover.py` (modify) — import `priority_for`; compute `seed_priority` once; pass child priority (from parent category) and seed priority into `enqueue`.
- `tests/test_db.py` (modify) — enqueue upsert + next_pending ordering tests.
- `tests/test_config.py` (modify) — `crawl_priority` load + `priority_for` tests.
- `tests/test_discover.py` (modify) — propagation integration tests.
- `README.md` (modify) — document `[crawl_priority]`.

`sources.py` is NOT modified — harvested seeds are enqueued inside `discover.crawl`, not in `sources.py`.

---

### Task 1: Frontier priority column, keep-highest `enqueue`, priority-ordered `next_pending`

**Files:**
- Modify: `src/onionwatch/db.py` (`SCHEMA` ~lines 37-40; `init_schema` ALTER loop ~lines 109-117; `enqueue` ~lines 175-181; `next_pending` ~lines 183-191)
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `enqueue(url, depth, priority=0)` (keep-highest upsert); `next_pending(limit)` ordered `priority DESC, depth ASC`; `frontier.priority` column.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_db.py`:

```python
def test_enqueue_stores_priority(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.enqueue("http://a.onion/", 0, 100)
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", ("http://a.onion/",)).fetchone()
    assert row["priority"] == 100


def test_enqueue_default_priority_is_zero(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.enqueue("http://a.onion/", 0)                 # no priority arg
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", ("http://a.onion/",)).fetchone()
    assert row["priority"] == 0


def test_enqueue_keeps_highest_priority_on_pending(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.enqueue("http://a.onion/", 1, 10)
    db.enqueue("http://a.onion/", 1, 100)            # higher -> upgrade
    db.enqueue("http://a.onion/", 1, 50)             # lower -> no change
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", ("http://a.onion/",)).fetchone()
    assert row["priority"] == 100
    assert db.count_frontier("pending") == 1         # still one row


def test_enqueue_does_not_touch_started_row(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.enqueue("http://a.onion/", 0, 10)
    db.next_pending(10)                              # flips to in_progress
    db.enqueue("http://a.onion/", 0, 999)           # must NOT change a started row
    row = db.conn.execute(
        "SELECT state, priority FROM frontier WHERE url=?",
        ("http://a.onion/",)).fetchone()
    assert row["state"] == "in_progress"
    assert row["priority"] == 10


def test_next_pending_orders_by_priority_then_depth(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.enqueue("http://low-shallow.onion/", 0, 0)
    db.enqueue("http://high-deep.onion/", 5, 100)
    db.enqueue("http://high-shallow.onion/", 1, 100)
    batch = db.next_pending(10)
    order = [r["url"] for r in batch]
    # priority DESC first: both priority-100 before the priority-0 one
    assert order.index("http://high-shallow.onion/") < order.index("http://low-shallow.onion/")
    assert order.index("http://high-deep.onion/") < order.index("http://low-shallow.onion/")
    # within priority 100, depth ASC: shallow before deep
    assert order.index("http://high-shallow.onion/") < order.index("http://high-deep.onion/")


def test_next_pending_all_zero_matches_depth_order(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.enqueue("http://d2.onion/", 2)
    db.enqueue("http://d0.onion/", 0)
    db.enqueue("http://d1.onion/", 1)
    order = [r["url"] for r in db.next_pending(10)]   # all priority 0 -> depth ASC
    assert order == ["http://d0.onion/", "http://d1.onion/", "http://d2.onion/"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_db.py -k "priority or next_pending or started_row" -v`
Expected: FAIL — `sqlite3.OperationalError: no such column: priority` (the column doesn't exist yet).

- [ ] **Step 3: Add the column, upsert, and ordering**

In `src/onionwatch/db.py`, update the `frontier` block in `SCHEMA` (currently lines 37-40):

```sql
CREATE TABLE IF NOT EXISTS frontier (
    url TEXT PRIMARY KEY, depth INTEGER,
    state TEXT DEFAULT 'pending', enqueued_at TEXT, attempts INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0
);
```

Append one line to the `init_schema` ALTER loop (after the `case_id` line, ~line 116):

```python
            "ALTER TABLE frontier ADD COLUMN priority INTEGER DEFAULT 0",
```

Replace `enqueue` (currently lines 175-181):

```python
    def enqueue(self, url, depth, priority=0) -> None:
        self.conn.execute(
            "INSERT INTO frontier (url, depth, state, enqueued_at, priority) "
            "VALUES (?, ?, 'pending', datetime('now'), ?) "
            "ON CONFLICT(url) DO UPDATE SET priority = excluded.priority "
            "  WHERE frontier.state = 'pending' "
            "    AND frontier.priority < excluded.priority",
            (url, depth, priority),
        )
        self.conn.commit()
```

Change the `ORDER BY` in `next_pending` (currently line 186):

```python
            "SELECT * FROM frontier WHERE state='pending' "
            "ORDER BY priority DESC, depth ASC LIMIT ?", (limit,))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_db.py -v`
Expected: PASS — the six new tests plus all pre-existing db tests (including `test_frontier_roundtrip`, whose duplicate `enqueue(...,0)` is now a no-op upsert since `0 < 0` is false).

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: priority column, keep-highest enqueue, priority-ordered next_pending"
```

---

### Task 2: `Config.crawl_priority` + `priority_for` helper

**Files:**
- Modify: `src/onionwatch/config.py` (`Config` dataclass ~lines 6-26; add `priority_for` after `load_config` ~line 49)
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Config.crawl_priority: dict` (default `{}`); `priority_for(category: str, weights: dict) -> int`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`:

```python
def test_load_config_crawl_priority(tmp_path):
    from onionwatch.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "concurrency = 8\n"
        "\n"
        "[crawl_priority]\n"
        "default = 0\n"
        "market = 100\n"
        "forum = 80\n"
    )
    cfg = load_config(str(cfg_file))
    assert cfg.crawl_priority == {"default": 0, "market": 100, "forum": 80}


def test_load_config_crawl_priority_absent_is_empty(tmp_path):
    from onionwatch.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("concurrency = 8\n")
    cfg = load_config(str(cfg_file))
    assert cfg.crawl_priority == {}


def test_priority_for_mapped_unmapped_and_default():
    from onionwatch.config import priority_for
    weights = {"default": 5, "market": 100}
    assert priority_for("market", weights) == 100     # mapped
    assert priority_for("forum", weights) == 5        # unmapped -> default
    assert priority_for("unknown", weights) == 5      # unknown -> default
    assert priority_for("market", {}) == 0            # no default -> 0
    assert priority_for("anything", {}) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_config.py -k "crawl_priority or priority_for" -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'crawl_priority'` / `ImportError: cannot import name 'priority_for'`.

- [ ] **Step 3: Add the field and helper**

In `src/onionwatch/config.py`, add a field to the `Config` dataclass (after `max_seeds_per_source`, ~line 26):

```python
    crawl_priority: dict = field(default_factory=dict)
```

Add the helper after `load_config` (~line 49):

```python
def priority_for(category: str, weights: dict) -> int:
    return int(weights.get(category, weights.get("default", 0)))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_config.py -v`
Expected: PASS — the three new tests plus all pre-existing config tests (`crawl_priority` is a known field, so `load_config` does not warn about it).

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/config.py tests/test_config.py
git commit -m "feat: Config.crawl_priority weight map + priority_for helper"
```

---

### Task 3: Propagate parent-category priority in `discover.crawl`

**Files:**
- Modify: `src/onionwatch/discover.py` (imports; `crawl` seed enqueues ~lines 95-96 & 103-104; child enqueue ~lines 151-156)
- Test: `tests/test_discover.py`

**Interfaces:**
- Consumes: `priority_for` (Task 2); `Config.crawl_priority` (Task 2); `enqueue(url, depth, priority)` (Task 1).
- Produces: child links enqueued at their parent category's weight; seeds enqueued at the `default` weight.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_discover.py` (reuses the module's existing `FakeClient`, `Config`, `Database`, `crawl`, `onion_host` imports and `@pytest.mark.asyncio`):

```python
@pytest.mark.asyncio
async def test_crawl_child_inherits_parent_category_priority(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    B = "http://bbbbbbbbbbbbbbbb.onion/"
    # A categorizes as marketplace; it links B
    pages = {A: f'<html><title>Shop</title><body>market vendor escrow '
                f'<a href="{B}">b</a></body></html>'}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=1, concurrency=1, per_host_delay=0,        # fetch A only
                 crawl_priority={"marketplace": 100})
    rules = {"marketplace": ["market", "vendor", "escrow"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run_pri", "2026-07-24T00:00:00",
                rules=rules)
    # B is still pending (A was the only fetch) and carries the parent's weight
    row = db.conn.execute(
        "SELECT state, priority FROM frontier WHERE url=?", (B,)).fetchone()
    assert row["state"] == "pending"
    assert row["priority"] == 100


@pytest.mark.asyncio
async def test_crawl_seed_uses_default_priority(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=0, concurrency=1, per_host_delay=0,        # don't drain
                 crawl_priority={"default": 7})
    await crawl(cfg, db, FakeClient({A: ""}), [A], "run_seed", "2026-07-24T00:00:00",
                rules={})
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", (A,)).fetchone()
    assert row["priority"] == 7


@pytest.mark.asyncio
async def test_crawl_no_priority_config_children_zero(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    B = "http://bbbbbbbbbbbbbbbb.onion/"
    pages = {A: f'<html><body>market vendor <a href="{B}">b</a></body></html>'}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=1, concurrency=1, per_host_delay=0)        # no crawl_priority
    rules = {"marketplace": ["market", "vendor"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run_zero", "2026-07-24T00:00:00",
                rules=rules)
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", (B,)).fetchone()
    assert row["priority"] == 0                                      # unchanged BFS
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_discover.py -k "priority" -v`
Expected: FAIL — children/seeds are enqueued with the default `priority=0`, so `test_crawl_child_inherits_parent_category_priority` (expects 100) and `test_crawl_seed_uses_default_priority` (expects 7) fail. (`test_crawl_no_priority_config_children_zero` passes even before the change — it guards the invariant after.)

- [ ] **Step 3: Wire propagation into `crawl`**

In `src/onionwatch/discover.py`, add the import near the other package imports at the top of the file (the module already imports from `.categorize`; add):

```python
from .config import priority_for
```

Compute the seed priority once, immediately after the crawl's `db.reset_state("in_progress", "pending")` line (~line 90):

```python
    seed_priority = config.crawl_priority.get("default", 0)
```

Update the harvested-seed enqueue (currently ~line 96):

```python
            db.enqueue(url, 0, seed_priority)
```

Update the watchlist-seed enqueue (currently ~line 104):

```python
        db.enqueue(seed_url, 0, seed_priority)
```

In the child-link block, compute the child priority from the parent category once (right after `cat = categorize(...)` and its `db.update_url(...)`, before the `if config.max_depth ...` loop, ~line 151), then pass it to `enqueue`:

```python
                child_priority = priority_for(cat.category, config.crawl_priority)
                if config.max_depth == 0 or depth < config.max_depth:
                    for link in extract_onion_links(res.html, url):
                        if db.get_url(link) is None:
                            db.upsert_url(link, onion_host(link) or "", "crawled",
                                          depth + 1, now)
                            db.enqueue(link, depth + 1, child_priority)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_discover.py -v`
Expected: PASS — the three new tests plus all pre-existing discover tests (seed enqueues now pass a third arg that defaults-equivalently to 0 when no `crawl_priority` is set).

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — all green (baseline 215 + new tests).

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/discover.py tests/test_discover.py
git commit -m "feat: propagate parent-category priority to child crawl frontier"
```

---

### Task 4: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the shipped behavior (Tasks 1-3). No code.

- [ ] **Step 1: Document `[crawl_priority]`**

Find the crawl/config section in `README.md` (search for `max_depth` or the crawl configuration description). Add a subsection describing crawl prioritization. Match the file's existing heading level and tone. Use exactly this content:

```markdown
### Crawl prioritization (optional)

By default the crawler is breadth-first: pages are fetched in discovery order,
shallowest first. To fetch high-value sites sooner, add a `[crawl_priority]`
table to `config.toml` mapping page categories (the same names used in
`categories.toml`) to integer weights:

    [crawl_priority]
    default     = 0
    marketplace = 100
    forum       = 80
    paste       = 60

When a page is crawled and categorized, every link it yields is enqueued at its
parent's category weight, and the frontier fetches highest-priority URLs first
(ties broken breadth-first). A URL linked from more than one page keeps the
highest priority it was ever offered. Seeds, and links from `unknown` or
unmapped-category pages, use `default` (0 if unset).

With no `[crawl_priority]` table, every priority is 0 and the crawl order is
unchanged — this feature is fully opt-in.
```

- [ ] **Step 2: Verify docs-only (no code touched)**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — unchanged suite (docs edit only).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document [crawl_priority] category-aware crawl prioritization"
```

---

## Notes for the executor

- The headline invariant is **opt-in-zero**: with no `[crawl_priority]`, priorities are all 0 and both `next_pending` order and crawl behavior are identical to today. `test_next_pending_all_zero_matches_depth_order` and `test_crawl_no_priority_config_children_zero` guard it — do not weaken them.
- `enqueue`'s `priority` parameter must default to `0` so the many existing 2-arg callers stay correct.
- Keep-highest: the upsert's `WHERE frontier.state = 'pending' AND frontier.priority < excluded.priority` clause is load-bearing — it prevents both downgrades and any change to a started/finished row. Do not drop it.
- `sources.py` is intentionally untouched; harvested seeds are enqueued in `discover.crawl`.
- Compute `child_priority` from `cat.category` (the parent page's category), NOT from any child property — the child's own category is unknown until it is itself fetched.
