"""Extract Indicators of Compromise (IOCs) from PDF documents."""

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Set

import pdfplumber
import requests

from utils.helpers import Helpers
from utils.termcolors import (BOLD, CYAN, DOTSEP, FOUND, GREEN, RED, RESET,
                              SEP, YELLOW)

helper = Helpers()

# Base directory
root = Path(__file__).resolve().parent


def extractor(pdf: str) -> list:
    """
    Open the PDF file and extract the text from each page.

    If the file size is greater than 10 MB, exit the program with an error message.

    Args:
        pdf (str): The PDF file to be read

    Returns:
        list: A list of text from each page of the PDF file.
    """
    size = os.path.getsize(pdf)
    large = round(size / (1024 * 1024))
    file_size_limit = 10240000
    if size > file_size_limit:
        sys.exit(f"{RED}[ERROR]{RESET} Limit file size to 10 MB or less. Your file is {large:,} MB.")
    else:
        with pdfplumber.open(pdf) as pdf_file:
            return [page.extract_text() for page in pdf_file.pages if page is not None]


def write_file(results: str, opt: str, report: Optional[str]) -> None:
    """
    Write the results to the file, and close the file.

    Args:
        results (str): The text that will be written to the file.
        opt (str): 'w' for write, 'a' for append.
        report (Optional[str]): The path to the PDF file you want to extract text from.
    """
    if report:
        file_output = root.joinpath(f"{os.path.basename(report).replace(' ', '_').replace('.pdf', '')}.txt")
        with open(file_output, opt, encoding="utf-8") as out:
            out.write(results)


class PDFWorker(object):
    """Processes PDF file."""

    def __init__(self):
        """Initialize the PDFWorker class."""
        self.counter = 0

    def processor(self, pdfdoc: str, output: bool, title: str) -> None:
        """
        It takes a PDF document, extracts the text, and writes it to a file.

        Args:
            pdfdoc (str): The PDF document to be processed
            output (bool): The output directory
            title (str): The title of the PDF document

        Raises:
            TypeError: If the PDF document is not a string.
        """
        print(f"{GREEN}\n[ Gathering IOCs ]{RESET}\n{DOTSEP}")

        pages = list(extractor(pdf=pdfdoc))
        try:
            text = "".join(filter(None, pages))
        except TypeError:
            print(f"Broken sentence: {''.join(filter(None, pages))}")
            raise

        self.get_patterns(output, title, pdfdoc, text)

    def process_domains(self, sorted_patterns: Set[str]) -> Set[str]:
        """
        Filters a set of domain patterns based on their top-level domain.

        Args:
            sorted_patterns (Set[str]): Domain names, sorted in alphabetical order.

        Returns:
            A set of domain names that have valid top-level domains (TLDs) and are not
            in the excluded list of TLDs.
        """
        new_patterns = set()
        exclude = ("gov", "foo", "py", "zip")  # add excluded tlds here
        for domain in sorted_patterns:
            tld = domain.split(".")[-1].lower()
            if tld in self.valid_tlds and tld not in exclude:
                new_patterns.add(domain)
        return new_patterns

    def print_and_write_patterns(self, key: str, patterns: Set[str], output: bool, title: str) -> None:
        """
        Prints and writes the patterns to a file if output is True.

        Args:
            key (str): The key or identifier for the patterns.
            patterns (Set[str]): A set of strings representing patterns that have been found.
            output (bool): Whether the results should be written to a file or not.
            title (str): The title of the report that will be written to a file.
        """
        pattern = "\n".join(patterns)
        if pattern:
            print(f"\n{FOUND}{BOLD}{key}{RESET}\n{SEP}\n{pattern}")
            if output:
                write_file(report=title, results=f"\n{key}\n{'-' * 15}\n{pattern}\n", opt="a")

    def get_patterns(self, output: bool, title: str, pdfdoc: str, text: str) -> None:
        """
        Searches for patterns in a given text and outputs the results to a file or console.

        Args:
            output (bool): A boolean value indicating whether to output the results to a file or not
            title (str): A string representing the title of the PDF document being analyzed
            pdfdoc (str): The path or location of the PDF document being analyzed
            text (str): The text to be analyzed for patterns and IOCs (indicators of compromise)
        """
        # header for the report
        if output:
            write_file(report=title, results=f"\nTITLE: {title} \nPATH: {pdfdoc}\n", opt="w")

        # detect language patterns in text.
        self.detect_language(output, title, text)

        # check for the tlds file and download if needed.
        self.download_tlds()

        # get the patterns from the text.
        for key, pvals in helper.patts(text).items():
            if pvals:
                sorted_patterns = sorted(set(pvals))
                if sorted_patterns:
                    self.counter += 1

                if key == "DOMAIN":
                    sorted_patterns = self.process_domains(set(sorted_patterns))

                if sorted_patterns:
                    self.counter += 1
                elif key == "DOMAIN":
                    self.counter -= 1

                self.print_and_write_patterns(key, set(sorted_patterns), output, title)

        if self.counter <= 0:
            print(f"{YELLOW}= No IOCs found ={RESET}")
            if output:
                write_file(report=title, results="= No IOCs found =", opt="w")

    @property
    def valid_tlds(self) -> set[str]:
        """
        Getter method for the valid_tlds class property.

        Returns:
            set: A set of valid top-level domains (TLDs).
        """
        valid_tlds = set()
        tlds_file = "tlds-alpha-by-domain.txt"
        with open(tlds_file, encoding="utf-8") as fileobj:
            for line in fileobj:
                tld = line.strip().lower()
                if tld and not tld.startswith("#"):
                    valid_tlds.add(tld)
        return valid_tlds

    def detect_language(self, output: bool, title: str, text: str) -> None:
        """
        Detects the language of the text.

        Args:
            output (bool): boolean value indicating whether to output the results to a file or not.
            title (str): The title of the report.
            text (str): The text to be analyzed for langauges.
        """
        detected_language = helper.detect_language(text)
        languages = ["ARABIC", "CYRILLIC", "CHINESE", "FARSI", "HEBREW"]
        for language in languages:
            if detected_language.get(language):
                spec = "".join(detected_language[language])
                if spec:
                    self.counter += 1
                    print(f"\n{FOUND}{BOLD}{language}{RESET}\n{SEP}\n{spec}")
                    if output:
                        write_file(report=title, results=f"\n{language}\n{'-' * 15}\n{spec}", opt="a")

    def download_tlds(self, age_limit_days: int = 3) -> Optional[str]:
        """
        Downloads TLDS file, saves it to a file, and returns the path to the file.

        Args:
            age_limit_days (int, optional, default=3): The number of days that the file can
                be old before it is updated.  Defaults to 3 days.

        Returns:
            The path to the downloaded file.
        """
        url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
        filename = "tlds-alpha-by-domain.txt"
        filepath = Path(filename)

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print(f"Error downloading file: {err}")
            return None

        if filepath.exists():
            mtime = filepath.stat().st_mtime
            mtime_datetime = datetime.fromtimestamp(mtime)

            now = datetime.now()
            delta = now - mtime_datetime
            age_limit = timedelta(days=age_limit_days)

            if delta > age_limit:
                print(f"TLDS file is older than {age_limit_days} days, updating...")
                try:
                    with open(filepath, "wb") as tlds_update:
                        tlds_update.write(response.content)
                except Exception as file_err:
                    print(f"Error updating file: {file_err}")
                    return None

        else:
            print("[!] The TLDS file is missing, downloading file...\n")
            try:
                with open(filepath, "wb") as tlds_file:
                    tlds_file.write(response.content)
            except Exception as download_err:
                print(f"Error downloading file: {download_err}")
                return None

            print(f"[+] The file {filename} has been downloaded and saved.")

        return str(filepath.resolve())


def main() -> None:
    """Main function that takes in command line arguments for a PDF document and extracts IOCs.

    Raises:
        SystemExit: If the file does not exist.
    """
    parser = argparse.ArgumentParser(description="PDF IOC Extractor")
    parser.add_argument(dest="pdf_doc", help="Path to single PDF document")
    parser.add_argument("-o", "--out", dest="output", action="store_true", help="Write output to file")
    args = parser.parse_args()

    if not Path(args.pdf_doc).exists():
        raise SystemExit(f"{RED}[ERROR]{RESET} No such file: {args.pdf_doc}")

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
    print(f"{CYAN}{BANNER}{RESET}")

    main()
