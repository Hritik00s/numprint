"""Tiny, dependency-free helpers for multiplication tables and parity checks."""

__all__ = ["is_even", "is_odd", "parity", "table", "print_tables"]


def is_even(number):
    """Return ``True`` when *number* is even.

    >>> is_even(4)
    True
    """
    return number % 2 == 0


def is_odd(number):
    """Return ``True`` when *number* is odd.

    >>> is_odd(7)
    True
    """
    return number % 2 != 0


def parity(number):
    """Return ``"even"`` or ``"odd"``.

    >>> parity(3)
    'odd'
    """
    return "odd" if is_odd(number) else "even"


def table(number, upto=None):
    """Return the multiplication table of *number* as a list of strings.

    *upto* defaults to *number*, so ``table(30)`` covers ``30 x 1``
    through ``30 x 30``.
    """
    if upto is None:
        upto = number
    return [f"{number} x {i} = {number * i}" for i in range(1, upto + 1)]


def print_tables(number, upto=None):
    """Print the multiplication table of *number*.

    >>> print_tables(3)
    3 x 1 = 3
    3 x 2 = 6
    3 x 3 = 9
    """
    for line in table(number, upto):
        print(line)