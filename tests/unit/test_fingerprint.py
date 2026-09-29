from vulnfab.core.fingerprint import FingerprintAllocator, compute_fingerprint, normalize_snippet

BASE = 'query = f"SELECT * FROM t WHERE id={uid}"'


def test_stable_under_whitespace_and_comments() -> None:
    a = compute_fingerprint("r", "a.py", BASE, "view")
    b = compute_fingerprint("r", "a.py", "  " + BASE + "   # trailing comment", "view")
    c = compute_fingerprint("r", "a.py", "/* c */\n" + BASE.replace(" = ", "  =  "), "view")
    assert a == b == c


def test_changes_when_code_changes() -> None:
    a = compute_fingerprint("r", "a.py", BASE, "view")
    assert a != compute_fingerprint("r", "a.py", BASE.replace("uid", "pid"), "view")
    assert a != compute_fingerprint("r2", "a.py", BASE, "view")
    assert a != compute_fingerprint("r", "b.py", BASE, "view")
    assert a != compute_fingerprint("r", "a.py", BASE, "other")


def test_comment_markers_inside_strings_are_kept() -> None:
    assert "# not a comment" in normalize_snippet('x = "# not a comment"')
    assert normalize_snippet("i-- \n j") == "i j" or normalize_snippet("i--\nj") == "i j"
    assert normalize_snippet("a--b") == "a--b"


def test_occurrence_index_separates_identical_snippets() -> None:
    alloc = FingerprintAllocator()
    first = alloc.allocate("r", "a.py", BASE, "f")
    second = alloc.allocate("r", "a.py", BASE, "f")
    assert first != second
    # deterministic across runs
    alloc2 = FingerprintAllocator()
    assert alloc2.allocate("r", "a.py", BASE, "f") == first
    assert alloc2.allocate("r", "a.py", BASE, "f") == second


def test_line_numbers_do_not_participate() -> None:
    # Fingerprint API takes no line number; shifting code cannot change it.
    assert compute_fingerprint("r", "a.py", BASE) == compute_fingerprint("r", "a.py", "\n\n" + BASE)
