"""LangGraph offline generation pipeline.

Runs BEFORE Greenmask's dump, not during it: profiles each PII column
detected by detector/, asks an LLM (or a local Faker fallback when no API key
is configured) for plausible replacement values, and writes them into the
Redis mapping store that lookup-service reads from at dump time. See
lookup-service/app/main.py's module docstring for why this ordering is what
makes the mapping store safe under Greenmask's parallel dump.

Privacy design decision: raw PII values are never sent to the LLM. Only
(entity_type, how many distinct values are needed) crosses the process
boundary to the model provider. The value -> replacement mapping is built
locally: an LLM-generated pool is paired 1:1 with the real distinct values
(fetched from Postgres, never transmitted externally) and stored keyed by
HMAC-SHA256(salt, original_value), same construction as
lookup-service.mapping_key. Because each real value maps to exactly one
replacement, per-column value frequency (and therefore the original
categorical distribution) is preserved automatically -- this is the practical
mechanism behind the distribution-preservation goal described in
arXiv:2505.02659, without needing to disclose real frequencies to the model.

Identity bundles (task 6): businessentityid-linked columns (firstname/
middlename/lastname in person.person, emailaddress in person.emailaddress)
are generated together so the same person gets a consistent name and a
derived e-mail across both tables, instead of two independently hashed
values that would silently break the name<->email relationship.
"""
import hashlib
import hmac
import json
import os
import random
import re
import string
import sys
from typing import TypedDict

import psycopg2
import redis
from faker import Faker

REPORT_PATH = os.environ.get("DETECTOR_REPORT_PATH", "/out/report.json")
DSN = (
    f"host={os.environ.get('DBHOST', 'playground-db')} "
    f"port={os.environ.get('DBPORT', '5432')} "
    f"user={os.environ.get('DBUSER', 'postgres')} "
    f"password={os.environ.get('DBPASSWORD', 'example')} "
    f"dbname={os.environ.get('ORIGINAL_DB_NAME', 'original')}"
)
REDIS_URL = os.environ.get("MAPPING_STORE_URL", "redis://localhost:6379/0")
SALT = os.environ.get("MAPPING_SALT", "").encode("utf-8")
LANGUAGE = os.environ.get("DETECTOR_LANGUAGE", "en")

CATEGORICAL_MAX = int(os.environ.get("GENERATOR_CATEGORICAL_MAX", "50"))
MAX_DISTINCT_PER_COLUMN = int(os.environ.get("GENERATOR_MAX_DISTINCT_PER_COLUMN", "500"))
MAX_IDENTITIES = int(os.environ.get("GENERATOR_MAX_IDENTITIES", "2000"))
BATCH_SIZE = int(os.environ.get("GENERATOR_BATCH_SIZE", "50"))

IDENTITY_KEY_COLUMN = "businessentityid"
IDENTITY_COLUMNS = {"firstname", "middlename", "lastname", "emailaddress"}

_redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# One Faker instance per locale, created lazily -- detector/detect.py tags
# every finding with a "language" ("ru"/"en") from a Unicode-script heuristic
# on the sampled values (see detect_language() there), and that flows through
# unchanged to here so replacements stay in the same script as the original
# data (Cyrillic names for Cyrillic columns, not the other way around).
_FAKER_LOCALES = {"en": "en_US", "ru": "ru_RU"}
_fake_instances: dict[str, Faker] = {}


def fake_for(language: str) -> Faker:
    locale = _FAKER_LOCALES.get(language, _FAKER_LOCALES["en"])
    if locale not in _fake_instances:
        _fake_instances[locale] = Faker(locale)
    return _fake_instances[locale]


# ---------------------------------------------------------------------------
# Backends: LLM (real replacement generation) or Faker (offline fallback so
# the pipeline is runnable without an API key -- required by the assignment).
# ---------------------------------------------------------------------------

# Faker's method names are the same across locales (fake.name(), fake.ssn()),
# but not every method is meaningfully localized -- ru_RU has no SSN/driver
# license/IBAN provider, since those are US-specific document types. For
# those we fall back to a locale-agnostic digit/letter pattern via
# `numerify`/`bothify` rather than pretending to implement real Russian
# document checksums (SNILS/INN have their own check-digit algorithms that
# are out of scope here) -- the goal is a plausible-shaped placeholder, not a
# valid one.
FAKER_BY_ENTITY = {
    "PERSON": lambda f: f.name(),
    "EMAIL_ADDRESS": lambda f: f.email(),
    "PHONE_NUMBER": lambda f: f.phone_number(),
    "LOCATION": lambda f: f.city(),
    "US_SSN": lambda f: f.ssn() if "ssn" in dir(f) else f.numerify("###-###-### ##"),
    "CREDIT_CARD": lambda f: f.credit_card_number(),
    "US_BANK_NUMBER": lambda f: f.credit_card_number(),
    "US_DRIVER_LICENSE": lambda f: f.bothify("??########").upper(),
    "IBAN_CODE": lambda f: f.iban(),
    "IP_ADDRESS": lambda f: f.ipv4(),
    "URL": lambda f: f.url(),
    "PASSWORD_HASH": lambda f: f.sha256(),
    "DATE_TIME": lambda f: f.date(),
}


class FakerBackend:
    name = "faker"

    def generate(self, entity_type: str, count: int, language: str = "en") -> list[str]:
        f = fake_for(language)
        gen = FAKER_BY_ENTITY.get(entity_type, lambda f: f.bothify("??????##"))
        seen: set[str] = set()
        out = []
        while len(out) < count:
            v = gen(f)
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def generate_full_names(self, count: int, language: str = "en") -> list[tuple[str, str]]:
        f = fake_for(language)
        seen: set[tuple[str, str]] = set()
        out = []
        while len(out) < count:
            pair = (f.first_name(), f.last_name())
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
        return out


class LLMBackend:
    """Wraps langchain_openai.ChatOpenAI. Only entity_type + count ever go
    into the prompt -- see module docstring."""

    name = "llm"

    def __init__(self, model: str):
        from langchain_openai import ChatOpenAI

        self._llm = ChatOpenAI(model=model, temperature=1.0)
        self._fallback = FakerBackend()

    def _ask_json_array(self, prompt: str) -> list:
        response = self._llm.invoke(prompt)
        text = response.content
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if not match:
            raise ValueError(f"LLM did not return a JSON array: {text[:200]!r}")
        return json.loads(match.group(0))

    def generate(self, entity_type: str, count: int, language: str = "en") -> list[str]:
        language_name = "Russian (Cyrillic script)" if language == "ru" else "English"
        pool: list[str] = []
        seen: set[str] = set()
        remaining = count
        while remaining > 0:
            batch = min(BATCH_SIZE, remaining)
            prompt = (
                f"Generate {batch} realistic, diverse, plausible {language_name} example values "
                f"of type '{entity_type}' for populating a test/demo database. Do not reuse real "
                f"people's data or real identifiers. Return ONLY a JSON array of {batch} "
                f"strings, no other text."
            )
            try:
                values = self._ask_json_array(prompt)
            except Exception as exc:  # noqa: BLE001 -- fall back, keep pipeline running
                print(f"generator: LLM call failed ({exc}), padding with faker", file=sys.stderr)
                values = self._fallback.generate(entity_type, batch, language)
            for v in values:
                v = str(v)
                if v not in seen:
                    seen.add(v)
                    pool.append(v)
            remaining = count - len(pool)
        return pool[:count]

    def generate_full_names(self, count: int, language: str = "en") -> list[tuple[str, str]]:
        language_name = "Russian (Cyrillic script)" if language == "ru" else "English"
        pool: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        remaining = count
        while remaining > 0:
            batch = min(BATCH_SIZE, remaining)
            prompt = (
                f"Generate {batch} realistic, diverse, plausible {language_name} full names "
                f"(first + last) for populating a test/demo HR database. Do not reuse real "
                f'people. Return ONLY a JSON array of {batch} objects like '
                f'{{"first": "...", "last": "..."}}.'
            )
            try:
                values = self._ask_json_array(prompt)
                pairs = [(str(v["first"]), str(v["last"])) for v in values]
            except Exception as exc:  # noqa: BLE001
                print(f"generator: LLM call failed ({exc}), padding with faker", file=sys.stderr)
                pairs = self._fallback.generate_full_names(batch, language)
            for p in pairs:
                if p not in seen:
                    seen.add(p)
                    pool.append(p)
            remaining = count - len(pool)
        return pool[:count]


def make_backend():
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if api_key:
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        print(f"generator: using LLM backend ({model})")
        return LLMBackend(model)
    print("generator: OPENAI_API_KEY not set, using local Faker fallback backend")
    return FakerBackend()


# ---------------------------------------------------------------------------
# Redis key helpers -- MUST match lookup-service/app/main.py exactly.
# ---------------------------------------------------------------------------


def mapping_key(schema: str, table: str, column: str, original_value: str) -> str:
    digest = hmac.new(SALT, original_value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"mapping:{schema}.{table}.{column}:{digest}"


def identity_key(businessentityid: str) -> str:
    return f"identity:{businessentityid}"


_CYRILLIC_TO_LATIN = str.maketrans(
    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
    "abvgdeejzijklmnoprstufhccss_y_eua",
)


def slugify(name: str) -> str:
    """Email local-parts stay ASCII regardless of the name's script --
    Cyrillic local-parts are technically legal (RFC 6531) but not what a
    plausible-looking test email address looks like in practice, so
    Russian names are transliterated rather than kept as-is."""
    ascii_name = name.lower().translate(_CYRILLIC_TO_LATIN)
    return re.sub(r"[^a-z]", "", ascii_name) or "user"


# ---------------------------------------------------------------------------
# LangGraph pipeline
# ---------------------------------------------------------------------------


class GeneratorState(TypedDict, total=False):
    findings: list[dict]
    plain_columns: list[dict]
    identity_tables: list[dict]
    writes: dict[str, str]
    identity_writes: dict[str, dict]


def node_load_report(state: GeneratorState) -> GeneratorState:
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        findings = json.load(f)
    # Only generate for columns detector/ actually put into Greenmask's
    # config (auto_applied) -- review-only findings are surfaced in
    # report.md for a human, not wired into the Cmd transformer, so
    # generating replacements for them would be wasted LLM calls.
    applied = [f for f in findings if f["auto_applied"]]
    plain = [f for f in applied if not f["identity_linked"]]
    identity_tables = [f for f in applied if f["identity_linked"]]
    print(f"generator: {len(plain)} plain columns, {len(identity_tables)} identity-linked columns")
    return {"findings": findings, "plain_columns": plain, "identity_tables": identity_tables}


def fetch_distinct_values(cur, schema, table, column, limit):
    cur.execute(
        f'select distinct "{column}" from "{schema}"."{table}" '
        f'where "{column}" is not null order by "{column}" limit %s',
        (limit,),
    )
    return [str(r[0]) for r in cur.fetchall()]


def node_generate_plain(state: GeneratorState, conn, backend) -> GeneratorState:
    writes: dict[str, str] = {}
    with conn.cursor() as cur:
        for item in state["plain_columns"]:
            schema, table, column = item["schema"], item["table"], item["column"]
            values = fetch_distinct_values(cur, schema, table, column, MAX_DISTINCT_PER_COLUMN)
            if not values:
                continue
            replacements = backend.generate(item["entity_type"], len(values), item.get("language", "en"))
            for original, replacement in zip(values, replacements):
                writes[mapping_key(schema, table, column, original)] = replacement
            print(
                f"generator: {schema}.{table}.{column} -> {len(values)} distinct values mapped "
                f"({'capped at ' + str(MAX_DISTINCT_PER_COLUMN) if len(values) == MAX_DISTINCT_PER_COLUMN else 'full coverage'})"
            )
    return {"writes": writes}


def node_generate_identities(state: GeneratorState, conn, backend) -> GeneratorState:
    identity_tables = state["identity_tables"]
    if not identity_tables:
        return {"identity_writes": {}}

    # businessentityid is the join key across every identity-linked table
    # (person.person, person.emailaddress, ...) -- union their id sets so a
    # person who only appears in one of the tables still gets a bundle.
    seen_tables = {(f["schema"], f["table"]) for f in identity_tables}
    ids: list[str] = []
    seen_ids: set[str] = set()
    with conn.cursor() as cur:
        for schema, table in seen_tables:
            if len(ids) >= MAX_IDENTITIES:
                break
            cur.execute(
                f'select distinct "{IDENTITY_KEY_COLUMN}" from "{schema}"."{table}" '
                f'where "{IDENTITY_KEY_COLUMN}" is not null order by "{IDENTITY_KEY_COLUMN}" limit %s',
                (MAX_IDENTITIES,),
            )
            for (row_id,) in cur.fetchall():
                row_id = str(row_id)
                if row_id not in seen_ids:
                    seen_ids.add(row_id)
                    ids.append(row_id)
                if len(ids) >= MAX_IDENTITIES:
                    break
    if not ids:
        return {"identity_writes": {}}

    # Names live in one table (firstname/lastname columns); that table's
    # detected language drives the whole bundle, including the (always-ASCII,
    # see slugify()) derived email.
    name_finding = next(
        (f for f in identity_tables if {"firstname", "lastname"} & {f["column"].lower()}),
        identity_tables[0],
    )
    language = name_finding.get("language", "en")

    name_pairs = backend.generate_full_names(len(ids), language)
    used_emails: set[str] = set()
    identity_writes: dict[str, dict] = {}
    for businessentityid, (first, last) in zip(ids, name_pairs):
        base = f"{slugify(first)}.{slugify(last)}"
        email = f"{base}@example.test"
        n = 1
        while email in used_emails:
            n += 1
            email = f"{base}{n}@example.test"
        used_emails.add(email)
        identity_writes[businessentityid] = {
            "firstname": first,
            "middlename": random.choice(string.ascii_uppercase),
            "lastname": last,
            "emailaddress": email,
        }
    print(f"generator: {len(identity_writes)} identity bundles generated (businessentityid-linked)")
    return {"identity_writes": identity_writes}


def node_persist(state: GeneratorState) -> GeneratorState:
    writes = state.get("writes", {})
    identity_writes = state.get("identity_writes", {})
    if writes:
        pipe = _redis.pipeline(transaction=False)
        for key, value in writes.items():
            pipe.set(key, value)
        pipe.execute()
    for businessentityid, bundle in identity_writes.items():
        _redis.hset(identity_key(businessentityid), mapping=bundle)
    print(f"generator: persisted {len(writes)} value mappings + {len(identity_writes)} identity bundles to Redis")
    return {}


def build_graph(conn, backend):
    from langgraph.graph import END, StateGraph

    graph = StateGraph(GeneratorState)
    graph.add_node("load_report", node_load_report)
    graph.add_node("generate_plain", lambda s: node_generate_plain(s, conn, backend))
    graph.add_node("generate_identities", lambda s: node_generate_identities(s, conn, backend))
    graph.add_node("persist", node_persist)

    graph.set_entry_point("load_report")
    graph.add_edge("load_report", "generate_plain")
    graph.add_edge("generate_plain", "generate_identities")
    graph.add_edge("generate_identities", "persist")
    graph.add_edge("persist", END)
    return graph.compile()


def main():
    global MAX_DISTINCT_PER_COLUMN, MAX_IDENTITIES

    conn = psycopg2.connect(DSN)
    conn.set_session(readonly=True, autocommit=True)
    backend = make_backend()

    # The 500/2000 defaults exist to bound LLM API cost/latency for a batch
    # run. Faker calls are local and effectively free, so a low cap there
    # only hurts diversity (uncovered values fall back to a placeholder in
    # lookup-service) for no benefit -- raise it unless the operator set an
    # explicit override.
    if backend.name == "faker":
        if "GENERATOR_MAX_DISTINCT_PER_COLUMN" not in os.environ:
            MAX_DISTINCT_PER_COLUMN = 50_000
        if "GENERATOR_MAX_IDENTITIES" not in os.environ:
            MAX_IDENTITIES = 50_000

    app = build_graph(conn, backend)
    app.invoke({"findings": []})


if __name__ == "__main__":
    main()
