"""Extract Indicators of Compromise (IOCs) from PDF documents."""

import argparse
from pathlib import Path

from rich.console import Console
from utils.helpers import Helpers
from utils.worker import PDFWorker

helper = Helpers()
console = Console(highlight=False)

# Base directory
root = Path(__file__).resolve().parent


class FileMissingError(Exception):
    """Custom exception for missing file."""

    def __init__(self, pdf_doc: argparse.Namespace) -> None:
        """Initializes the FileMissingError class."""
        super().__init__(f"[ERROR] No such file: {pdf_doc}")


def main() -> None:
    """Main function that takes in command line arguments for a PDF document and extracts IOCs.

    Raises:
        FileMissingError: If the file does not exist.
    """
    parser = argparse.ArgumentParser(description="PDF IOC Extractor")
    parser.add_argument(dest="pdf_doc", help="Path to single PDF document")
    parser.add_argument("-o", "--out", dest="output", action="store_true", help="Write output to file")
    args = parser.parse_args()

    # Check if pdf file exists
    if not Path(args.pdf_doc).exists():
        raise FileMissingError(args.pdf_doc)

    title = Path(args.pdf_doc).name  # get filename for report title
    worker = PDFWorker()  # instantiate PDFWorker class
    worker.tlds_file()  # check for the tlds file and download if needed.
    worker.processor(pdfdoc=args.pdf_doc, output=args.output, title=title)  # process PDF document


if __name__ == "__main__":
    BANNER = r"""
        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor
    """
    console.print(f"{BANNER}", style="cyan bold")

    main()
