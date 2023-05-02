"""Color constants used to colorize text in the terminal."""

from colorama import Fore, Style, init

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