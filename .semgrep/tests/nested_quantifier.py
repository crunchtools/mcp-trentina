# Fixture for trentina-nested-quantifier-regex.
import re

# ruleid: trentina-nested-quantifier-regex
EVIL = re.compile(r"^(a+)+$")

# ruleid: trentina-nested-quantifier-regex
WORDS = re.compile(r"(\w*\s?)*done")


def find(text):
    # ruleid: trentina-nested-quantifier-regex
    return re.search(r"(?:x+y)+", text)


def repeat(text):
    # ruleid: trentina-nested-quantifier-regex
    return re.match(r"(ab*){2,}", text)


# ok: trentina-nested-quantifier-regex
SAFE = re.compile(r"^(abc)+$")

# ok: trentina-nested-quantifier-regex
CLASS = re.compile(r"([a+])+")

# ok: trentina-nested-quantifier-regex
ESCAPED = re.compile(r"(\+)+")

# ok: trentina-nested-quantifier-regex
BOUNDED = re.compile(r"(a+){2}")
