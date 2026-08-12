"""Presidio-based PII detector.

Samples real values from Postgres per column (not just the column name) so
detection generalizes beyond a fixed name dictionary — this is why we picked
Presidio (content-based NER + regex + checksum recognizers) over
postgresql_anonymizer's anon.detect(), which is a static column-name lookup
table (see ARCHITECTURE.md). A small name-based heuristic list is still kept
as a *fallback* for structured short values Presidio's recognizers are known
to miss (hashes, salts, raw ID numbers with no locale-specific format).

Output:
  detector/out/report.json                  -- machine-readable findings
  detector/out/report.md                     -- human-readable report
  detector/out/transformation.detected.yml   -- Greenmask config fragment
"""
import json
import os
from collections import Counter, defaultdict

import psycopg2
import yaml
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

SAMPLE_SIZE = int(os.environ.get("DETECTOR_SAMPLE_SIZE", "200"))
MIN_HIT_RATIO = float(os.environ.get("DETECTOR_MIN_HIT_RATIO", "0.2"))
SCHEMAS = os.environ.get("DETECTOR_SCHEMAS", "person,humanresources,sales").split(",")
LANGUAGE = os.environ.get("DETECTOR_LANGUAGE", "en")
OUT_DIR = os.environ.get("DETECTOR_OUT_DIR", "/out")

# AnalyzerEngine() defaults to en_core_web_lg (400MB, downloaded at runtime if
# missing) -- pin it to the sm model we actually install at build time
# (docker/detector/Dockerfile) so `docker compose run detector` doesn't
# re-download hundreds of MB on every run.
NLP_CONFIGURATION = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": LANGUAGE, "model_name": "en_core_web_sm"}],
}

DSN = (
    f"host={os.environ.get('DBHOST', 'playground-db')} "
    f"port={os.environ.get('DBPORT', '5432')} "
    f"user={os.environ.get('DBUSER', 'postgres')} "
    f"password={os.environ.get('DBPASSWORD', 'example')} "
    f"dbname={os.environ.get('ORIGINAL_DB_NAME', 'original')}"
)

NAME_HEURISTICS = {
    "nationalidnumber": "US_SSN",
    "passwordhash": "PASSWORD_HASH",
    "passwordsalt": "PASSWORD_HASH",
}

# The lightweight en_core_web_sm NER model reliably false-positives on short
# ALLCAPS reference codes (currency/country ISO codes, enum-like "type"/
# "category"/"group" columns), tagging them ORGANIZATION or DATE_TIME. Two
# cheap, explainable filters catch most of it without hurting recall on real
# PII: (1) a small deny-list of column-name substrings for known enum/code
# columns, and (2) dropping FK/PK columns outright, since those are
# relationship/reference codes by construction -- masking them protects no
# one and only risks breaking the meaning of lookup tables. Entity types that
# stayed noisy even after that (ORGANIZATION, DATE_TIME, NRP) are still
# reported for a human to review, just not auto-applied to the Greenmask
# config -- see AUTO_APPLY_ENTITY_TYPES.
DENY_NAME_SUBSTRINGS = ("code", "type", "category", "flag", "group")
AUTO_APPLY_ENTITY_TYPES = {
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "US_SSN",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "PASSWORD_HASH",
}
MIN_SAMPLE_SIZE = int(os.environ.get("DETECTOR_MIN_SAMPLE_SIZE", "10"))

TEXTUAL_TYPES = ["character varying", "character", "text"]

# businessentityid is a surrogate FK, never touched -- but it is the join key
# used later (generator/, lookup-service) to keep name+email consistent across
# person.person and person.emailaddress. Recorded here so the detected config
# fragment can pass it through as context instead of Greenmask dropping it.
IDENTITY_KEY_COLUMN = "businessentityid"
IDENTITY_COLUMNS = {"firstname", "middlename", "lastname", "emailaddress"}


def list_text_columns(cur):
    cur.execute(
        """
        select c.table_schema, c.table_name, c.column_name, c.data_type
        from information_schema.columns c
        join information_schema.tables t
          on t.table_schema = c.table_schema and t.table_name = c.table_name
        where c.table_schema = any(%s)
          and t.table_type = 'BASE TABLE'
          and c.data_type = any(%s)
        order by 1, 2, 3
        """,
        (SCHEMAS, TEXTUAL_TYPES),
    )
    return cur.fetchall()


def table_has_column(cur, schema, table, column):
    cur.execute(
        """
        select 1 from information_schema.columns
        where table_schema = %s and table_name = %s and column_name = %s
        """,
        (schema, table, column),
    )
    return cur.fetchone() is not None


def load_key_columns(cur):
    """Every column that participates in a PRIMARY KEY or FOREIGN KEY
    constraint, across the schemas we scan -- used to exclude reference/enum
    codes from PII detection (see DENY_NAME_SUBSTRINGS comment above)."""
    cur.execute(
        """
        select tc.table_schema, tc.table_name, kcu.column_name
        from information_schema.table_constraints tc
        join information_schema.key_column_usage kcu
          on tc.constraint_name = kcu.constraint_name
         and tc.table_schema = kcu.table_schema
        where tc.table_schema = any(%s)
          and tc.constraint_type in ('PRIMARY KEY', 'FOREIGN KEY')
        """,
        (SCHEMAS,),
    )
    return {(schema, table, column.lower()) for schema, table, column in cur.fetchall()}


def sample_column(cur, schema, table, column):
    cur.execute(
        f'select "{column}" from "{schema}"."{table}" where "{column}" is not null limit %s',
        (SAMPLE_SIZE,),
    )
    return [str(r[0]) for r in cur.fetchall() if str(r[0]).strip()]


CYRILLIC_RANGE = ("Ѐ", "ӿ")


def script_counts(values: list[str]) -> tuple[int, int]:
    """Cyrillic vs Latin *letter* counts across the sample. Digit-only
    "document" columns (phone numbers, SSN-shaped IDs) carry no script
    signal at all -- a phone number looks identical in Russian and English
    -- so this can legitimately return (0, 0), which detect_language() must
    not silently read as "en"."""
    cyrillic = latin = 0
    for value in values:
        for ch in value:
            if CYRILLIC_RANGE[0] <= ch <= CYRILLIC_RANGE[1]:
                cyrillic += 1
            elif ch.isalpha():
                latin += 1
    return cyrillic, latin


def detect_language(cyrillic: int, latin: int, table_default: str = "en") -> str:
    """Script-based heuristic, not a statistical language model -- a direct
    Unicode-range majority vote. A statistical detector (e.g. langdetect)
    needs a decent amount of running text to be reliable and is known to
    misfire on short tokens, exactly what PII values are (names, IDs), so
    this is both simpler and more robust here. When the column itself has no
    alphabetic signal (cyrillic == latin == 0, e.g. a phone-number-only
    column), falls back to `table_default` -- the majority language among
    the table's *other* PII columns -- rather than defaulting to "en" as if
    a real detection happened; see main()'s two-pass assembly."""
    if cyrillic == 0 and latin == 0:
        return table_default
    return "ru" if cyrillic > latin else "en"


def classify(analyzer, column, values):
    # Known-sensitive columns are trusted by name over content: Presidio has
    # no recognizer for salts/hashes, and short/opaque values give it nothing
    # to work with anyway.
    heuristic = NAME_HEURISTICS.get(column.lower())
    if heuristic:
        return heuristic, 1.0, "name-heuristic"
    if not values or len(values) < MIN_SAMPLE_SIZE:
        return None
    counts = Counter()
    for value in values:
        for r in analyzer.analyze(text=value, language=LANGUAGE):
            counts[r.entity_type] += 1
    if counts:
        entity_type, hits = counts.most_common(1)[0]
        ratio = hits / len(values)
        if ratio >= MIN_HIT_RATIO:
            return entity_type, ratio, "presidio"
    return None


def main():
    conn = psycopg2.connect(DSN)
    conn.set_session(readonly=True, autocommit=True)
    nlp_engine = NlpEngineProvider(nlp_configuration=NLP_CONFIGURATION).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[LANGUAGE])
    findings = []
    with conn.cursor() as cur:
        key_columns = load_key_columns(cur)
        columns = list_text_columns(cur)
        for schema, table, column, _dtype in columns:
            column_lower = column.lower()
            if (schema, table, column_lower) in key_columns:
                continue
            if any(s in column_lower for s in DENY_NAME_SUBSTRINGS) and column_lower not in NAME_HEURISTICS:
                continue
            values = sample_column(cur, schema, table, column)
            result = classify(analyzer, column, values)
            if not result:
                continue
            entity_type, ratio, source = result
            has_identity_key = column_lower in IDENTITY_COLUMNS and table_has_column(
                cur, schema, table, IDENTITY_KEY_COLUMN
            )
            cyrillic, latin = script_counts(values)
            findings.append(
                {
                    "schema": schema,
                    "table": table,
                    "column": column,
                    "entity_type": entity_type,
                    "hit_ratio": round(ratio, 2),
                    "source": source,
                    "sample_size": len(values),
                    "identity_linked": has_identity_key,
                    "auto_applied": entity_type in AUTO_APPLY_ENTITY_TYPES,
                    "_cyrillic": cyrillic,
                    "_latin": latin,
                }
            )

    # Second pass: columns with no alphabetic signal of their own (phone
    # numbers, SSN-shaped IDs) inherit the majority language of the *other*
    # PII columns in the same table, instead of defaulting to "en" as if a
    # real detection happened -- see detect_language()'s docstring.
    table_script_totals = defaultdict(lambda: [0, 0])  # (schema, table) -> [cyrillic, latin]
    for item in findings:
        totals = table_script_totals[(item["schema"], item["table"])]
        totals[0] += item["_cyrillic"]
        totals[1] += item["_latin"]
    for item in findings:
        cyrillic, latin = table_script_totals[(item["schema"], item["table"])]
        table_default = "ru" if cyrillic > latin else "en"
        item["language"] = detect_language(item.pop("_cyrillic"), item.pop("_latin"), table_default)

    write_report(findings)
    write_config_fragment(findings)
    applied = sum(1 for f in findings if f["auto_applied"])
    print(
        f"detector: {len(findings)} PII columns found across {len(SCHEMAS)} schemas "
        f"({applied} auto-applied, {len(findings) - applied} flagged for human review only)"
    )


def write_report(findings):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "report.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    by_table = defaultdict(list)
    for item in findings:
        by_table[(item["schema"], item["table"])].append(item)

    applied = sum(1 for f in findings if f["auto_applied"])
    lines = [
        "# PII detection report",
        "",
        f"Всего колонок с PII: {len(findings)} "
        f"({applied} автоматически включены в конфиг Greenmask, "
        f"{len(findings) - applied} только для ручного ревью — см. AUTO_APPLY_ENTITY_TYPES в detect.py)",
        "",
    ]
    for (schema, table), items in sorted(by_table.items()):
        lines.append(f"## {schema}.{table}")
        lines.append("")
        lines.append("| колонка | категория | язык | hit ratio | источник | identity-linked | в конфиге |")
        lines.append("|---|---|---|---|---|---|---|")
        for item in items:
            lines.append(
                f"| {item['column']} | {item['entity_type']} | {item['language']} | {item['hit_ratio']} "
                f"| {item['source']} | {item['identity_linked']} | {item['auto_applied']} |"
            )
        lines.append("")
    with open(os.path.join(OUT_DIR, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_config_fragment(findings):
    by_table = defaultdict(list)
    for item in findings:
        if not item["auto_applied"]:
            continue
        by_table[(item["schema"], item["table"])].append(item)

    transformation = []
    for (schema, table), items in sorted(by_table.items()):
        columns = [{"name": item["column"]} for item in items]
        # identity-linked tables also get businessentityid passed through so
        # lookup-service can resolve/generate the shared identity bundle
        # (see lookup-service/app/main.py -- resolve_identity()).
        if any(item["identity_linked"] for item in items):
            columns.insert(0, {"name": IDENTITY_KEY_COLUMN})
        transformation.append(
            {
                "schema": schema,
                "name": table,
                "transformers": [
                    {
                        "name": "Cmd",
                        "params": {
                            "executable": "python3",
                            "args": [
                                "/opt/lookup-service/main.py",
                                "--schema",
                                schema,
                                "--table",
                                table,
                            ],
                            "driver": {"name": "json"},
                            "validate": True,
                            "columns": columns,
                        },
                    }
                ],
            }
        )
    with open(os.path.join(OUT_DIR, "transformation.detected.yml"), "w", encoding="utf-8") as f:
        yaml.dump({"transformation": transformation}, f, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
    main()
