from numprint import is_even, is_odd, parity, print_tables, table


def test_is_even():
    assert is_even(0)
    assert is_even(42)
    assert not is_even(7)


def test_is_odd():
    assert is_odd(7)
    assert not is_odd(42)


def test_parity():
    assert parity(2) == "even"
    assert parity(3) == "odd"


def test_table_default_upto_is_number():
    lines = table(30)
    assert len(lines) == 30
    assert lines[0] == "30 x 1 = 30"
    assert lines[-1] == "30 x 30 = 900"


def test_print_tables(capsys):
    print_tables(3)
    assert capsys.readouterr().out.splitlines() == [
        "3 x 1 = 3", "3 x 2 = 6", "3 x 3 = 9",
    ]