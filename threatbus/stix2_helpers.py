from typing import Tuple, Union
from stix2patterns.v21.pattern import Pattern

"""
A collection of helper functions to work with STIX-2 objects and / or patterns
"""


def is_point_equality_ioc(pattern_str: str) -> bool:
    """
    Predicate to check if a STIX-2 pattern is a point-IoC, i.e., if the pattern
    only consists of a single EqualityComparisonExpression
    @param pattern_str The STIX-2 pattern string to inspect
    """
    try:
        pattern = Pattern(pattern_str)
        # InspectionListener https://github.com/oasis-open/cti-pattern-validator/blob/e926d0a14adf88de08acb908a51db1f453c13647/stix2patterns/v21/inspector.py#L5
        # E.g.,   pattern = "[domain-name:value = 'evil.com']"
        # =>           il = pattern_data(comparisons={'domain-name': [(['value'], '=', "'evil.com'")]}, observation_ops=set(), qualifiers=set())
        # =>  cybox_types = ['domain-name']
        il = pattern.inspect()
        cybox_types = list(il.comparisons.keys())
        return (
            len(il.observation_ops) == 0
            and len(il.qualifiers) == 0
            and len(il.comparisons) == 1
            and len(cybox_types) == 1  # must be point-indicator (one field only)
            and len(il.comparisons[cybox_types[0]][0])
            == 3  # ('value', '=', 'evil.com')
            and il.comparisons[cybox_types[0]][0][1] == "="  # equality comparison
        )
    except Exception:
        return False


def split_object_path_and_value(pattern_str: str) -> Union[Tuple[str, str], None]:
    """
    Splits a STIX-2 pattern from a point IoC into the object_path and the
    ioc_value of that pattern (e.g., [domain-name:value = 'evil.com'] is split
    to `domain-name:value` and `evil.com`. Returns None if the pattern is not
    a point-ioc pattern.
    @param pattern_str The STIX-2 pattern to split
    @return the object_path and ioc_value of the pattern or None
    """
    if not is_point_equality_ioc(pattern_str):
        return None
    (object_path, ioc_value) = pattern_str[1:-1].split("=", 1)
    object_path, ioc_value = object_path.strip(), ioc_value.strip()
    if ioc_value.startswith("'") and ioc_value.endswith("'"):
        ioc_value = ioc_value[1:-1]
    return object_path, ioc_value
