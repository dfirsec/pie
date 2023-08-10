"""Utility class."""

import re
from collections.abc import Iterator


class Helpers:
    """Helper functions for the program."""

    def regex(self, category: str, pattern_name: str) -> re.Pattern:
        """Regex function for patterns.

        Args:
            category (str): The category of regex patterns to use.
            pattern_name (str): The name of the regex pattern to use.

        Returns:
            re.Pattern: The regex pattern to use.
        """
        patterns = {
            "languages": {
                "arabic": re.compile(r"[\u0600-\u06FF\u0698\u067E\u0686\u06AF]"),
                "chinese": re.compile(r"[\u4E00-\u9FFF]"),
                "kanji": re.compile(r"[\u4E00-\u9FFF\u3400-\u4DBF\uF900-\uFAFF]"),
                "han-unification": re.compile(
                    r"^[\u4E00-\u9FFF\u3400-\u4DBF\u20000-\u2A6DF\u2A700-\u2B73F\u2B740-\u2B81F\u2B820-\u2CEAF\u2CEB0-\u2EBEF\u30000-\u3134F\uF900-\uFAFF\u2E80-\u2EFF\u31C0-\u31EF\u3000-\u303F\u2FF0-\u2FFF\u3300-\u33FF\uFE30-\uFE4F\uF900-\uFAFF\u2F800-\u2FA1F\u3200-\u32FF\u1F200-\u1F2FF\u2F00-\u2FDF]+$",
                ),
                "farsi": re.compile(r"[\u0600-\u06FF\u0698\u067E\u0686\u06AF]"),
                "cyrillic": re.compile(r"[\u0400-\u04FF]"),
                "hebrew": re.compile(r"[\u0590-\u05FF\uFB2A-\uFB4E]"),
                "devanagari": re.compile(r"[\u0900-\u0954]"),
            },
            "hashes": {
                "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
                "sha1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
                "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
                "sha512": re.compile(r"\b[A-Fa-f0-9]{128}\b"),
            },
            "net-related": {
                "ipv4": re.compile(
                    r"(((?![0])(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\[\.\]|\.))){3}(25[0-5]|"
                    r"2[0-4][0-9]|[01]?[0-9][0-9]?)",
                ),
                "mac": re.compile(r"^[a-fA-F0-9]2(:[a-fA-F0-9]2)5$"),
            },
            "web-related": {
                "domain": re.compile(
                    r"([A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?:\[\.\]|\.)(?![a-z-]*.[i\.e]$"
                    r"|[e\.g]$)(?:[a-z]"
                    r"{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)",
                ),
                "email": re.compile(
                    r"([a-zA-Z0-9_.+-]+(\[@\]|@)(?!fireeye)[a-zA-Z0-9-.]+(\.|\[\.\])(?![a-z-]+\.gov|gov)"
                    r"([a-zA-Z0-9-.]{2,6}\b))",
                ),
                "url": re.compile(
                    r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]"
                    r"{1,6}\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=\*]*))",
                ),
                "webfile": re.compile(
                    r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(hta|html|htm|htmls|java|jsp|js|php|asp$|aspx))",
                ),
            },
            "file-related": {
                "archive": re.compile(
                    r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(zip|7z|jar|gz|rar|xz|tar|tar\.gz))",
                ),
                "binary": re.compile(
                    r"(([^\s|\W])+([a-z-A-Z0-9\-\_]|[\u4E00-\u9FFF]|[\u0400-\u04FF])+((?:\.exe)|"
                    r"(?:\.msi)|(?:\.dll)|(?:\.bin)))",
                ),
                "env_var": re.compile(r"(\%+[a-zA-Z0-9]+\%.*[^\"])"),
                "image": re.compile(
                    r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(bmp|gif|jpg|jpeg|png|svg|tiff|wepb))",
                ),
                "misc_file": re.compile(r"(([^\s|\W])+([a-z-A-Z0-9\-\_])+((?:\.txt)|(?:\.csv)))"),
                "office": re.compile(r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+\.(doc|docx|xls|xlsx|pdf))"),
                "script": re.compile(
                    r"(([^\s|(\"])+[a-z-A-Z0-9\-\_]+((?:\.vbs)|(?:\.sh)|(?:\.bat)|(?:\.ps1)|(?:\.py)))",
                ),
                "windir": re.compile(r"\b[a-zA-Z]{1}:\\?\\(?:\w+\\?).+$"),
            },
            "misc": {
                "btc": re.compile(r"(^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$)"),
                "base64": re.compile(
                    r"(^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$)",
                ),
                "geolocation": re.compile(r"^((\-?|\+?)?\d+(\.\d+)?),\s*((\-?|\+?)?\d+(\.\d+)?)$"),
            },
            "pii": {
                "address": re.compile(
                    r"(^(\d+)\s?([A-Za-z](?=\s))?\s(.*?)\s([^ ]+?)\s?((?<=\s)APT)?\s?((?<=\s)\d*)?$)",
                ),
                "cc": re.compile(
                    r"^(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}"
                    r"|27[01][0-9]|2720)[0-9]{12}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}"
                    r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$",
                ),
                "phone": re.compile(
                    r"(^(?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]"
                    r"?\d{4}(?![\d-]))|(?:("
                    r"?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-]))\$)",
                ),
                "po_box": re.compile(r"P\.? ?O\.? Box \d+"),
                "ssn": re.compile(
                    r"((?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[- ]"
                    r"(?!00))[0-9]{2}[- ](?!0000)[0-9]{4}",
                ),
                "zip_code": re.compile(r"\b\d{5}(?:[-\s]\d{4})?\b"),
            },
        }
        return patterns[category][pattern_name]

    def reiter(self, regex: re.Pattern[str], text: str) -> Iterator[str]:
        """Returns an iterator over all the matches of a regex in a string.

        Args:
            regex (re.Pattern[str]): The regular expression to use.
            text (str): The text to be searched.

        Returns:
            Iterator[str]: An iterator over all the matches of a regex in a string
        """
        return (match.group() for match in re.finditer(regex, text.lower()))

    def detect_language(self, text: str) -> dict[str, Iterator[str]]:
        """Returns language.

        Args:
            text (str): The text to be searched.

        Returns:
            Dict[str, Iterator[str]]: regex match by language.
        """
        return {
            "KANJI": self.reiter(self.regex("languages", "kanji"), text),
            "ARABIC": self.reiter(self.regex("languages", "arabic"), text),
            "CHINESE": self.reiter(self.regex("languages", "chinese"), text),
            "FARSI": self.reiter(self.regex("languages", "farsi"), text),
            "CYRILLIC": self.reiter(self.regex("languages", "cyrillic"), text),
            "HEBREW": self.reiter(self.regex("languages", "hebrew"), text),
            "HAN": self.reiter(self.regex("languages", "han-unification"), text),
            "DEVANAGARI": self.reiter(self.regex("languages", "devanagari"), text),
        }

    def patts(self, text: str) -> dict[str, Iterator[str]]:
        """Returns content type found.

        Args:
            text (str): The text to be searched.

        Returns:
            Dict[str, Iterator[str]]: regex match by content type.
        """
        return {
            "ARCHIVE": self.reiter(self.regex("file-related", "archive"), text),
            "BINARY": self.reiter(self.regex("file-related", "binary"), text),
            "BTC": self.reiter(self.regex("misc", "btc"), text),
            "DOMAIN": self.reiter(self.regex("web-related", "domain"), text),
            "EMAIL": self.reiter(self.regex("web-related", "email"), text),
            "ENVIRONMENT VARIABLE": self.reiter(self.regex("file-related", "env_var"), text),
            "MISC FILE": self.reiter(self.regex("file-related", "misc_file"), text),
            "IMAGE": self.reiter(self.regex("file-related", "image"), text),
            "IPV4": self.reiter(self.regex("net-related", "ipv4"), text),
            "GEOLOCATION": self.reiter(self.regex("misc", "geolocation"), text),
            "MAC": self.reiter(self.regex("net-related", "mac"), text),
            "MD5": self.reiter(self.regex("hashes", "md5"), text),
            "OFFICE/PDF": self.reiter(self.regex("file-related", "office"), text),
            "PHONE": self.reiter(self.regex("pii", "phone"), text),
            "SCRIPT": self.reiter(self.regex("file-related", "script"), text),
            "SHA1": self.reiter(self.regex("hashes", "sha1"), text),
            "SHA256": self.reiter(self.regex("hashes", "sha256"), text),
            "URL": self.reiter(self.regex("web-related", "url"), text),
            "WEB FILE": self.reiter(self.regex("web-related", "webfile"), text),
            "WIN DIR": self.reiter(self.regex("file-related", "windir"), text),
        }
