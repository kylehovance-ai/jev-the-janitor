"""Every .py in the package and the tests must compile on Python 3.11, the floor in pyproject.

0.5.0 shipped an f-string with a backslash inside a replacement field, which 3.12 accepts
(PEP 701) and 3.11 rejects at import, so the suite failed on the 3.11 CI runners after every
local run had been on a newer interpreter. This test runs on 3.12+ and re-applies 3.11's rules
to every f-string with the tokenizer, which on 3.12+ splits f-strings into FSTRING_START,
FSTRING_MIDDLE and FSTRING_END with ordinary tokens for the expression parts. Inside a
replacement field, 3.11 refuses:

  * a backslash anywhere, including inside a nested string literal;
  * the enclosing f-string's own quote (or its triple, for a triple-quoted f-string);
  * a ``#`` anywhere, including inside a nested string literal;
  * a line break, unless the f-string is triple-quoted.

Each rule applies to every enclosing f-string, not only the innermost, because 3.11 read the
outermost f-string as one string token. On 3.11 itself the interpreter is the check, so the
test skips there.
"""
from __future__ import annotations

import io
import sys
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("janitor", "tests")


def python_files():
    for d in SOURCE_DIRS:
        yield from sorted((ROOT / d).rglob("*.py"))


def quote_of(fstring_start: str) -> str:
    """The quote sequence that opens an f-string: one of ' " ''' \"\"\"."""
    text = fstring_start.lstrip("fFrRbBuU")
    return text[:3] if text[:3] in ("'''", '"""') else text[:1]


def violations_in(source: str, name: str):
    found = []
    stack = []  # (quote, start_row) of every open f-string, outermost first
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for tok in tokens:
        kind, text, (row, col) = tok.type, tok.string, tok.start
        where = f"{name}:{row}:{col + 1}"
        if kind == tokenize.FSTRING_END:
            stack.pop()
            continue
        if kind == tokenize.FSTRING_MIDDLE:
            enclosing = stack[:-1]  # its own literal text is fine; it sits inside the OUTER expressions
        else:
            enclosing = list(stack)
        for quote, start_row in enclosing:
            if "\\" in text:
                found.append(f"{where}: backslash inside an f-string replacement field ({text!r})")
            if "#" in text:
                found.append(f"{where}: '#' inside an f-string replacement field ({text!r})")
            if quote in text:
                found.append(f"{where}: the enclosing f-string's quote {quote} reused inside its replacement field ({text!r})")
            if len(quote) == 1 and (row != start_row or kind in (tokenize.NL, tokenize.NEWLINE)):
                found.append(f"{where}: a replacement field of a single-quoted f-string spans lines")
        if kind == tokenize.FSTRING_START:
            stack.append((quote_of(text), row))
    return found


@pytest.mark.skipif(sys.version_info < (3, 12), reason="on 3.11 the interpreter itself is the check")
def test_every_fstring_compiles_on_python_311():
    problems = []
    for path in python_files():
        problems += violations_in(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
    assert not problems, "\n".join(problems)


@pytest.mark.skipif(sys.version_info < (3, 12), reason="on 3.11 the interpreter itself is the check")
def test_the_guard_catches_each_rule():
    # the shape that shipped in 0.5.0: a backslash-escaped quote inside a nested string
    assert any("backslash" in v for v in violations_in('x = f"{" ".join(f"<i class=\\\'a\\\'>{t}</i>" for t in y)}"\n', "s"))
    # the same quote reused inside the field
    assert any("quote" in v for v in violations_in('x = f"{d["k"]}"\n', "s"))
    # a comment character inside a nested string
    assert any("'#'" in v for v in violations_in("x = f\"{'#'}\"\n", "s"))
    # a field that spans lines in a single-quoted f-string
    assert any("spans lines" in v for v in violations_in('x = f"{(1 +\n 2)}"\n', "s"))
    # and the shapes 3.11 accepts
    assert violations_in('x = f"{d[\'k\']} {\' \'.join(y)}"\n', "s") == []
    assert violations_in('x = f"""{d["k"]}"""\n', "s") == []
    assert violations_in('x = f"""{(1 +\n 2)}"""\n', "s") == []
    assert violations_in('x = f"a\\nb {y}"\n', "s") == []  # a backslash in the literal part is fine
    assert violations_in('x = f"{y}" f\'{z["k"]}\'\n', "s") == []  # concatenated pieces keep their own quotes
    assert violations_in("x = f'{f\"{y}\"}'\n", "s") == []  # a nested f-string with the other quote
