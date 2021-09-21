"""Implementation core of scanner."""

from datetime import datetime
import json
import os
import sqlite3
from typing import List, Tuple

import util


def check_attachments(path: str) -> bool:
    """Scan attachments at a given path for fake gifs, output results to stdout.

    Return whether suspicious files were found.
    """
    # Validate path
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        print("Cannot find folder for attachments here")
        return False

    # Find all gifs
    files = os.popen(f"find {path} -iname '*.gif'").read()
    files_ls = [f for f in files.split("\n") if f]

    # Drop out if none found
    if len(files_ls) == 0:
        print("Could not find any GIF files")
        return False
    else:
        print(f"Found {len(files_ls)} files to scan")

    # Get header of each file
    filedict = {}
    for file in files_ls:
        with open(file, "rb") as f:
            filedict[file] = f.read(6)

    # Check headers
    bad_files = []
    for file, header in filedict.items():
        if header not in [b"GIF87a", b"GIF89a"]:
            bad_files.append((file, header))

    # Output
    print(f"Found {len(bad_files)} suspicious files")
    for file, header in bad_files:
        print(f"\t{str(header)[2:-1]}\t{file}")
    return bool(bad_files)


def check_database(path: str) -> bool:
    """Scan a database at a given path for attack evidence.

    Return whether attack was detected.
    """
    # Validate path
    if not os.path.exists(path):
        print("Cannot find folder for database here")
        return False

    # Connect to db
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # Execute query
    cursor.execute(
        """
        SELECT "CASCADEFAIL"
        FROM ZLIVEUSAGE
        WHERE ZLIVEUSAGE.ZHASPROCESS NOT IN (SELECT Z_PK FROM ZPROCESS);
    """
    )
    output = cursor.fetchall()
    found_bad = bool(output)
    if found_bad:
        print("Found evidence of compromise in DataUsage.sqlite")
    else:
        print("Found no evidence of compromise in DataUsage.sqlite")
    return found_bad


def get_backup_data() -> List[Tuple[str, str, datetime]]:
    """Get backup udids and most recent dates.

    Returns list of (udid, datetime_str, datetime)s.
    """
    # Get backup data
    command = [
        "ibackuptool",
        "--list",
        "--formatter json",
        "--quiet",
    ]
    backups = json.loads(util.run_cmd_list(command))

    # Check backups exist
    if not backups:
        print("No mobile backups on device")
        return []

    # Check backups are unencrypted
    usable = [backup for backup in backups if not backup["encrypted"]]
    if not usable:
        print("All backups on device are encrypted")
        return []

    # Parse the datetimes and return data
    date_fmt = "%m/%d/%Y, %I:%M:%S %p"
    output = []
    for backup in usable:
        output.append(
            (
                backup["udid"],
                backup["date"],
                datetime.strptime(backup["date"], date_fmt),
            )
        )

    return output


def dump_backup_data(udid: str, attachments=True, datausagedb=True) -> str:
    """Dump backup data for a given backup udid, return path to dump."""
    # Generate dump directory and clean
    dump_dir = "/tmp/backup_data_" + udid.replace("-", "")
    util.wipe_dir(dump_dir)
    os.mkdir(dump_dir)

    # Dump data for attachments
    if attachments:
        command = [
            "ibackuptool",
            f"--backup {udid}",
            "--report backup.files",
            f"--extract {dump_dir}",
            r"--regex-filter '^Media/Library/SMS/Attachments/.*\.gif$'",
            "--quiet",
        ]
        util.run_cmd_list(command)

    # Dump data for datausage db
    if datausagedb:
        command = [
            "ibackuptool",
            f"--backup {udid}",
            "--report backup.files",
            f"--extract {dump_dir}",
            r"--regex-filter '^Library/Databases/DataUsage.sqlite$'",
            "--quiet",
        ]
        util.run_cmd_list(command)

    # Return path to dump
    return dump_dir


def validate_ibackup_install() -> bool:
    """Validate that ibackuptools is installed by running help."""
    command = [
        "ibackuptool",
        "-h",
    ]
    out = util.run_cmd_list(command)
    return bool(out)
