# <vendor directory>/_VENDOR.md

Vendored from `kbg-platform`. Check this record with `python tools/vendor_check.py <vendor directory>` (add `--base <path to the base's package directory>` to compare with a checkout).

- source repository: <URL or local clone of kbg-platform, read only>
- source path: `bases/core/src/kbg_platform_core/`
- base commit: `<40-character commit id from git rev-parse HEAD in the clone>`
- vendored on: <date>
- line endings: <as in the base; mark this directory -text in .gitattributes so git never converts them>

## Files taken

State is one of `byte-for-byte` (identical to the base), `adapted` (changed, logged below), `trimmed` (only imports or exports removed, logged below). `local change` is `-` for byte-for-byte, otherwise an id from "Local changes". The last column is `same` for byte-for-byte, otherwise the base file's sha256. Print rows for the files now present with `--print-table`.

| file | state | local change | sha256 (this copy) | sha256 (base) |
|---|---|---|---|---|
| `example.py` | byte-for-byte | - | `0000000000000000000000000000000000000000000000000000000000000000` | same |

## Files deliberately not taken

One bullet per file you chose not to copy, with the reason. The check fails if one of these appears in the directory.

- `example_declined.py`: <why it does not fit this product>

## Local changes (every one is logged here)

One bullet per change, starting with its id in bold. An `adapted` or `trimmed` file must name an id that is listed here.

- **L1, `example.py`**: <what changed and why>

## How to take an upstream change

Diff the base between the recorded commit and the new one for the file, apply the wanted hunks by hand, update the hashes and the base commit above, log the merge here, and run the check again.
