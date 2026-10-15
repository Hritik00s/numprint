# numprint

Tiny, dependency-free helpers for multiplication tables and parity checks.

## Install

```console
pip install git+https://github.com/Hritik0os/numprint.git
```

## Usage

```python
from numprint import print_tables, is_even, parity

print_tables(50)     # 50 x 1 ... 50 x 50
print_tables(30)     # 30 x 1 ... 30 x 30

is_even(4)           # True
is_odd(4)            # False
parity(7)            # 'odd'
```

Or from the command line:

```console
$ numprint 12
12 x 1 = 12
12 x 2 = 24
...
12 x 12 = 144
```

## API

| Function | Description |
|---|---|
| `print_tables(n, upto=None)` | Print the table of `n`. `upto` defaults to `n`. |
| `table(n, upto=None)` | Same, returned as a list of strings. |
| `is_even(n)` | `True` if `n` is even. |
| `is_odd(n)` | `True` if `n` is odd. |
| `parity(n)` | `'even'` or `'odd'`. |

## Development

```console
pip install -e ".[dev]"
pytest
```

## License

MIT