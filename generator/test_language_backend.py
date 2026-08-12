"""Standalone check for language-aware generation (task: EN+RU support).

Adventure Works itself is entirely English, so the "ru" branch never fires
during the real pipeline run -- this script proves it independently by
feeding synthetic English *and* Russian sample values (a few different
"document" shapes: person name, phone, an SSN/SNILS-shaped ID) through the
same detect_language()/FakerBackend code paths the real pipeline uses, and
asserting the output script matches the input script.

Mirrors detector/detect.py's two-pass table-language assembly: a digit-only
column (phone number, SSN-shaped ID) carries no script signal by itself --
"+7 (912) 345-67-89" looks the same regardless of language -- so its language
is inherited from the other PII columns of the same (simulated) table rather
than naively detected as "en".

Run: docker compose run --rm --entrypoint python generator test_language_backend.py
(--entrypoint override needed: the image's default ENTRYPOINT is
["python", "generate.py"], see docker/generator/Dockerfile)
"""
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, ".")

from generate import FakerBackend  # noqa: E402

CYRILLIC_RANGE = ("Ѐ", "ӿ")


def script_counts(values: list[str]) -> tuple[int, int]:
    cyrillic = latin = 0
    for value in values:
        for ch in value:
            if CYRILLIC_RANGE[0] <= ch <= CYRILLIC_RANGE[1]:
                cyrillic += 1
            elif ch.isalpha():
                latin += 1
    return cyrillic, latin


def detect_language(cyrillic: int, latin: int, table_default: str = "en") -> str:
    if cyrillic == 0 and latin == 0:
        return table_default
    return "ru" if cyrillic > latin else "en"


def is_cyrillic(text: str) -> bool:
    return any(CYRILLIC_RANGE[0] <= ch <= CYRILLIC_RANGE[1] for ch in text)


# Each dict simulates one table's PII columns: PERSON carries the script
# signal, US_SSN/PHONE_NUMBER are digit-only and must inherit it.
TABLES = {
    "en": {
        "PERSON": ["John Smith", "Mary Johnson", "Robert Brown"],
        "US_SSN": ["123-45-6789", "987-65-4321"],
        "PHONE_NUMBER": ["+1 (555) 123-4567"],
    },
    "ru": {
        "PERSON": ["Иван Петров", "Мария Сидорова", "Алексей Кузнецов"],
        # SNILS-shaped: 11 digits, XXX-XXX-XXX XX -- not a real checksum,
        # see FAKER_BY_ENTITY's comment in generate.py.
        "US_SSN": ["112-233-445 95", "998-877-665 12"],
        "PHONE_NUMBER": ["+7 (912) 345-67-89"],
    },
}


def main():
    backend = FakerBackend()
    failures = []

    for expected_language, entities in TABLES.items():
        # pass 1: raw script counts per column, and the table-level total
        per_column = {entity_type: script_counts(values) for entity_type, values in entities.items()}
        table_cyrillic = sum(c for c, _ in per_column.values())
        table_latin = sum(l for _, l in per_column.values())
        table_default = "ru" if table_cyrillic > table_latin else "en"

        # pass 2: resolve each column's language, generate, check the script
        for entity_type, values in entities.items():
            cyrillic, latin = per_column[entity_type]
            detected = detect_language(cyrillic, latin, table_default)
            status = "OK" if detected == expected_language else "MISMATCH"
            if status != "OK":
                failures.append(f"detect_language({entity_type}={values}) = {detected}, expected {expected_language}")
            print(f"[{status}] detect_language {entity_type}/{expected_language}: {values} -> {detected}")

            generated = backend.generate(entity_type, 3, detected)
            alpha_values = [v for v in generated if any(c.isalpha() for c in v)]
            script_ok = all(is_cyrillic(v) == (expected_language == "ru") for v in alpha_values)
            status = "OK" if script_ok else "MISMATCH"
            if status != "OK":
                failures.append(f"generate({entity_type}, lang={detected}) produced wrong script: {generated}")
            print(f"[{status}] generate {entity_type}/{detected}: {generated}")

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("All language-detection / locale-generation checks passed.")


if __name__ == "__main__":
    main()
