# PDF IOC Extractor (PIE)

![Generic badge](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

Quick method to extract Indicators of Compromise (IOCs) from an Threat Intel Report in PDF format.  It can output the results to a file or to the console.

## Installation

```text
git clone https://github.com/dfirsec/pie.git
cd pie
pip install -r requirements.txt
```

## Dependencies

- argparse
- os
- sys
- datetime
- pathlib
- typing
- pdfplumber
- requests

## Usage

`python pie.py [-h] [-o] pdf_doc`

### Positional arguments

`pdf_doc`: The path to the PDF document to be processed.

### Optional arguments

`-h, --help`: show the help message and exit.
`-o, --out`: Write output to file.

### Example run

```text
python pie.py Intel_Report.pdf

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