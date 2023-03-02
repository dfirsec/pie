"""
Takes a PDF document as an argument, extracts the text from the PDF, and then searches the text for IOCs.
"""
import argparse
import contextlib
import os
import sys
import unicodedata
from pathlib import Path
from typing import Optional

import pdfplumber
from tld import is_tld
from tld.utils import update_tld_names
from utils import Helpers, Termcolors

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.0.9"
__description__ = "Extract Indicators of Compromise (IOCs) from PDF documents."

HELPER = Helpers()
TC = Termcolors()

# update/sync tld names
update_tld_names()

# Base directory
PARENT = Path(__file__).resolve().parent


def extractor(pdf: str):
    """
    > If the file size is greater than 10 MB, exit the program with an error message. Otherwise, open
    the PDF file and extract the text from each page.

    :param pdf: The PDF file to be read
    :return: A list of strings.
    """
    size = os.path.getsize(pdf)
    large = round(size / (1024 * 1024))
    if size > 10240000:
        sys.exit(f"{TC.RED}[ERROR]{TC.RESET} Limit file size to 10 MB or less. Your file is {large:,} MB.")
    else:
        with pdfplumber.open(pdf) as pdf_file:
            return [page.extract_text() for page in pdf_file.pages if page is not None]


def write_file(results: str, opt: str, report: Optional[str]) -> None:
    """
    If the report is not empty, then write the results to a file.

    :param results: the text that will be written to the file
    :param opt: 'w' for write, 'a' for append
    :param report: the path to the PDF file
    """
    if report:
        file_output = PARENT.joinpath(f"{os.path.basename(report).replace(' ', '_').replace('.pdf', '')}.txt")
        with open(file_output, opt, encoding="utf-8") as out:
            out.write(results)


class PDFWorker:
    """Processes PDF file."""

    def __init__(self):
        self.counter = 0

    def processor(self, pdfdoc: str, output: bool, title: str) -> None:
        """
        It takes a PDF document, extracts the text, and writes it to a file.

        :param pdf_doc: The PDF document to be processed
        :param output: The output directory
        :param title: The title of the PDF document
        """
        print(f"{TC.DOTSEP}\n{TC.GREEN} [ Gathering IOCs ]{TC.RESET}")
        pages = list(extractor(pdf=pdfdoc))
        try:
            text = "".join(filter(None, pages))
        except TypeError:
            print(f"Broken sentence: {''.join(filter(None, pages))}")
            raise

        self.get_patterns(output, title, pdfdoc, text)

    def get_patterns(self, output: bool, title: str, pdfdoc: str, text: str) -> None:
        # sourcery skip: low-code-quality
        """Create output file"""
        if output:
            write_file(report=title, results=f"\nTITLE: {title} \nPATH: {pdfdoc}\n", opt="w")

        # Language detection
        detected_language = HELPER.detect_language(text)
        languages = ["ARABIC", "CYRILLIC", "CHINESE", "FARSI", "HEBREW"]
        for language in languages:
            if detected_language.get(language):
                self.counter += 1
                if spec := "".join(detected_language[language]):
                    print(f"\n{TC.FOUND}{TC.BOLD}{language}{TC.RESET}\n{TC.SEP}\n{spec}")
                    if output:
                        write_file(report=title, results=f"\n{language}\n{'-' * 15}\n{spec}", opt="a")

        # Detect patterns
        exclude = ("gov", "foo", "bar", "py")
        for key, pattern in HELPER.patts(text).items():
            if pattern:
                self.counter += 1
                sorted_patterns = sorted(set(pattern))

                if key == "DOMAIN":
                    for domain in pattern:
                        tld = domain.split(".")[-1]
                        with contextlib.suppress(ValueError):
                            while not is_tld(tld) or tld in exclude:
                                sorted_patterns.remove(domain)
                pattern = "\n".join(sorted_patterns)
            if pattern:
                print(f"\n{TC.FOUND}{TC.BOLD}{key}{TC.RESET}\n{TC.SEP}\n{pattern}")
                if output:
                    write_file(report=title, results=f"\n{key}\n{'-' * 15}\n{pattern}\n", opt="a")

        if self.counter == 0:
            print(f"{TC.YELLOW}= No IOCs found ={TC.RESET}")
            if output:
                write_file(report=title, results="= No IOCs found =", opt="w")

    # def get_patterns(self, output: bool, title: str, pdfdoc: str, text: str) -> None:
    #     """Create output file"""
    #     lang_results = ""
    #     patts_results = ""

    #     if output:
    #         write_file(report=title, results=f"\nTITLE: {title} \nPATH: {pdfdoc}\n", opt="w")

    #     # Language detection
    #     detected_language = HELPER.detect_language(text)
    #     languages = ["ARABIC", "CYRILLIC", "CHINESE", "FARSI", "HEBREW"]
    #     for language in languages:
    #         if detected_language.get(language):
    #             self.counter += 1
    #             if spec := "".join(detected_language[language]):
    #                 lang_results += f"\n{language}\n{'-' * 15}\n{spec}\n"

    #     # Detect patterns
    #     exclude = ("gov", "foo", "bar", "py")
    #     for key, pattern in HELPER.patts(text).items():
    #         if pattern:
    #             self.counter += 1
    #             sorted_patterns = sorted(set(pattern))

    #             if key == "DOMAIN":
    #                 for domain in pattern:
    #                     tld = domain.split(".")[-1]
    #                     with contextlib.suppress(ValueError):
    #                         while not is_tld(tld) or tld in exclude:
    #                             sorted_patterns.remove(domain)
    #             pattern = "\n".join(sorted_patterns)
    #         if pattern:
    #             patts_results += f"\n{key}\n{'-' * 15}\n{pattern}\n"

    #     if lang_results or patts_results:
    #         if lang_results:
    #             print(f"\n{TC.FOUND}LANGUAGES{TC.RESET}\n{lang_results}")
    #         if patts_results:
    #             print(f"\n{TC.FOUND}PATTERNS{TC.RESET}\n{patts_results}")
    #         if output:
    #             write_file(report=title, results=lang_results + patts_results, opt="a")
    #     else:
    #         print(f"{TC.YELLOW}= No IOCs found ={TC.RESET}")
    #         if output:
    #             write_file(report=title, results="= No IOCs found =", opt="w")


def main():
    """
    Main program
    """
    parser = argparse.ArgumentParser(description="PDF IOC Extractor")
    parser.add_argument(dest="pdf_doc", help="Path to single PDF document")
    parser.add_argument("-o", "--out", dest="output", action="store_true", help="Write output to file")
    args = parser.parse_args()

    if not Path(args.pdf_doc).exists():
        raise SystemExit(f"{TC.RED}[ERROR]{TC.RESET} No such file: {args.pdf_doc}")

    title = os.path.basename(args.pdf_doc)
    worker = PDFWorker()
    worker.processor(pdfdoc=args.pdf_doc, output=args.output, title=title)


if __name__ == "__main__":
    BANNER = r"""
        ____     ____   ______
       / __ \   /  _/  / ____/
      / /_/ /   / /   / __/
     / ____/  _/ /   / /___
    /_/      /___/  /_____/

    PDF IOC Extractor
    """
    print(f"{TC.CYAN}{BANNER}{TC.RESET}")
    main()
