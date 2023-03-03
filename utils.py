"""Utility class"""
import re

from colorama import Fore, Style, init


class Helpers:
    """Helper functions for the program"""

    def __init__(self):
        pass

    def regex(self, category: str, pattern_name: str):  # sourcery skip: docstrings-for-functions
        patterns = {
            "languages": {
                "arabic": re.compile(r"[\u0600-\u06FF\u0698\u067E\u0686\u06AF]"),
                "chinese": re.compile(r"[\u4E00-\u9FFF]"),
                "cyrillic": re.compile(r"[\u0400-\u04FF]"),
                "hebrew": re.compile(r"[\u0590-\u05FF\uFB2A-\uFB4E]"),
                "han-unification": re.compile(
                    r"^[\\u4E00-\\u9FFF\\u3400-\\u4DBF\\u20000-\\u2A6DF\\u2A700-\\u2B73F\\u2B740-\\u2B81F\\u2B820-\\"
                    r"u2CEAF\\u2CEB0-\\u2EBEF\\u30000-\\u3134F\\uF900-\\uFAFF\\u2E80-\\u2EFF\\u31C0-\\u31EF\\u3000-\\"
                    r"u303F\\u2FF0-\\u2FFF\\u3300-\\u33FF\\uFE30-\\uFE4F\\uF900-\\uFAFF\\u2F800-\\u2FA1F\\u3200-\\"
                    r"u32FF\\u1F200-\\u1F2FF\\u2F00-\\u2FDF]+$"
                ),
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
                    r"2[0-4][0-9]|[01]?[0-9][0-9]?)"
                ),
                "mac": re.compile(r"^[a-fA-F0-9]2(:[a-fA-F0-9]2)5$"),
            },
            "web-related": {
                "domain": re.compile(
                    r"([A-Za-z0-9]+(?:[\-|\.|][A-Za-z0-9]+)*(?:\[\.\]|\.)(?![a-z-]*.[i\.e]$"
                    r"|[e\.g]$)(?:[a-z]"
                    r"{2,4})\b|(?:\[\.\][a-z]{2,4})(?!@)$)"
                ),
                "email": re.compile(
                    r"([a-zA-Z0-9_.+-]+(\[@\]|@)(?!fireeye)[a-zA-Z0-9-.]+(\.|\[\.\])(?![a-z-]+\.gov|gov)"
                    r"([a-zA-Z0-9-.]{2,6}\b))"
                ),
                "url": re.compile(
                    r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]"
                    r"{1,6}\b([-a-zA-Z0-9@:%_\+.~#?&\/\/=\*]*))"
                ),
                "webfile": re.compile(
                    r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(hta|html|htm|htmls|java|jsp|js|php|asp$|aspx))"
                ),
            },
            "file-related": {
                "archive": re.compile(
                    r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(zip|7z|jar|gz|rar|xz|tar|tar\.gz))"
                ),
                "binary": re.compile(
                    r"(([^\s|\W])+([a-z-A-Z0-9\-\_]|[\u4E00-\u9FFF]|[\u0400-\u04FF])+((?:\.exe)|"
                    r"(?:\.msi)|(?:\.dll)|(?:\.bin)))"
                ),
                "env_var": re.compile(r"(\%+[a-zA-Z0-9]+\%.*[^\"])"),
                "image": re.compile(
                    r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+(\.|\[\.\])(bmp|gif|jpg|jpeg|png|svg|tiff|wepb))"
                ),
                "misc_file": re.compile(r"(([^\s|\W])+([a-z-A-Z0-9\-\_])+((?:\.txt)|(?:\.csv)))"),
                "office": re.compile(r"(([^\s|\d\W*])+[a-z-A-Z0-9\-\_ ]+\.(doc|docx|xls|xlsx|pdf))"),
                "script": re.compile(
                    r"(([^\s|(\"])+[a-z-A-Z0-9\-\_]+((?:\.vbs)|(?:\.sh)|(?:\.bat)|(?:\.ps1)|(?:\.py)))"
                ),
                "windir": re.compile(
                    r"([a-zA-Z]{1}:(\\|\\\\|\/\/)(?<![a-zA-Z]:\/\/)[a-zA-Z0-9\-\_\\\/].+([^\s|\"]+)[^\.\"\r\n])"
                ),
            },
            "misc": {
                "btc": re.compile(r"(^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$)"),
                "base64": re.compile(
                    r"(^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$)"
                ),
                "latlon": re.compile(r"^((\-?|\+?)?\d+(\.\d+)?),\s*((\-?|\+?)?\d+(\.\d+)?)$"),
            },
            "pii": {
                "address": re.compile(
                    r"(^(\d+)\s?([A-Za-z](?=\s))?\s(.*?)\s([^ ]+?)\s?((?<=\s)APT)?\s?((?<=\s)\d*)?$)"
                ),
                "cc": re.compile(
                    r"(^4[0-9]{12}(?:[0-9]{3})?$)|(^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}"
                    r"|27[01][0-9]|2720)[0-9]{12}$)|(3[47][0-9]{13})|(^3(?:0[0-5]|[68][0-9])[0-9]{11}$)"
                    r"|(^6(?:011|5[0-9]{2})[0-9]{12}$)|(^(?:2131|1800|35\d{3})\d{11}$)",
                    re.MULTILINE,
                ),
                "date": re.compile(
                    r"(?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?("
                    r"?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug"
                    r"\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|("
                    r"?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug"
                    r"\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)["
                    r"0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}"
                ),
                "phone": re.compile(
                    r"(^(?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]"
                    r"?\d{4}(?![\d-]))|(?:("
                    r"?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-]))\$)"
                ),
                "po_box": re.compile(r"P\.? ?O\.? Box \d+"),
                "ssn": re.compile(
                    r"((?!000|666|333)0*(?:[0-6][0-9][0-9]|[0-7][0-6][0-9]|[0-7][0-7][0-2])[- ]"
                    r"(?!00))[0-9]{2}[- ](?!0000)[0-9]{4}"
                ),
                "zip_code": re.compile(r"\b\d{5}(?:[-\s]\d{4})?\b"),
            },
        }
        return patterns[category][pattern_name]

    def reiter(self, regex: re.Pattern[str], text: str):  # sourcery skip: docstrings-for-functions
        return (x.group() for x in re.finditer(regex, text.lower()))

    def detect_language(self, text: str):  # sourcery skip: docstrings-for-functions
        return {
            "ARABIC": self.reiter(self.regex("languages", "arabic"), text),
            "CHINESE": self.reiter(self.regex("languages", "chinese"), text),
            "CYRILLIC": self.reiter(self.regex("languages", "cyrillic"), text),
            "HEBREW": self.reiter(self.regex("languages", "hebrew"), text),
            "HAN": self.reiter(self.regex("languages", "han-unification"), text),
            "DEVANAGARI": self.reiter(self.regex("languages", "devanagari"), text),
        }

    def patts(self, text: str):  # sourcery skip: docstrings-for-functions
        return {
            "ARCHIVE": self.reiter(self.regex("hashes", "md5"), text),
            "BINARY": self.reiter(self.regex("hashes", "sha1"), text),
            "BTC": self.reiter(self.regex("hashes", "sha256"), text),
            "DOMAIN": self.reiter(self.regex("web-related", "domain"), text),
            "EMAIL": self.reiter(self.regex("web-related", "email"), text),
            "ENVIRONMENT VARIABLE": self.reiter(self.regex("file-related", "env_var"), text),
            "MISC FILE": self.reiter(self.regex("file-related", "misc_file"), text),
            "IMAGE": self.reiter(self.regex("file-related", "image"), text),
            "IPV4": self.reiter(self.regex("net-related", "ipv4"), text),
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


class Termcolors:
    """
    Color constants used to colorize text in the terminal.
    """

    # Initialize colorama
    init()

    BOLD = Fore.LIGHTWHITE_EX
    CYAN = Fore.CYAN
    GRAY = Fore.LIGHTBLACK_EX
    GREEN = Fore.LIGHTGREEN_EX
    RED = Fore.RED
    YELLOW = Fore.LIGHTYELLOW_EX
    RESET = Style.RESET_ALL
    SEP = f"{GRAY}--------------{RESET}"
    DOTSEP = f"{GRAY}{'.' * 20}{RESET}"
    FOUND = f"{CYAN}\u2BA9 {RESET}"
