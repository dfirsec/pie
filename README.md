# PDF IOC Extractor (PIE)

![Generic badge](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

Quick method to extract Indicators of Compromise (IOCs) from a Threat Intel Report in PDF format. It can output the results to a file or to the console.

## Prerequisites

Relies on `uv` for dependency management. If you don't have it installed, use one of the following methods:

### macOS / Linux

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Windows

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Pip

```bash
pip install uv
```

## Installation

```bash
git clone https://github.com/dfirsec/pie.git
cd pie
uv sync
```

## Dependencies

- rich
- pdfplumber
- requests

## Usage

Run the script directly using `uv run`:

```bash
uv run pie.py [-h] [-o] pdf_doc
```

Another option is to activate the environment manually:

```bash
# macOS/Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate

python pie.py [-h] [-o] pdf_doc
```

### Positional arguments

`pdf_doc`: The path to the PDF document to be processed.

### Optional arguments

`-h, --help`: show the help message and exit.
`-o, --out`: Write output to file.

### Example run

```console
$ uv run pie.py Intel_Report.pdf

        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor

....................
 Gathering IOCs...

EMAIL
--------------
waco-leaks@emailinbox.123
xoap1@emailinbox.123

DOMAIN
--------------
emailinbox.123
whoisleaky.com
werearetheleaks.com

URL
--------------
file://123.45.67.89/weirdfile.png

MD5
--------------
01efc52acec2b1986aabe2472401a2cf
3c6b9bde7e06064f56d54bbcdd39b9cf

SHA1
--------------
302fc52acec2b1121aabe2473471a2cf89919ecb
6b699ee60c0o8cb2d9d87c35895a3a24b0937d85
```

## License

This script is released under the MIT License. See LICENSE.md for more information.
