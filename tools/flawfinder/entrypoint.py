#!/usr/bin/env python3
"""GitHub Action entrypoint for flawfinder."""
import os
import shlex
import subprocess
import sys

output = os.environ.get('FLAWFINDER_OUTPUT') or 'flawfinder-output.txt'
args = shlex.split(sys.argv[1]) if len(sys.argv) > 1 else []

with open(output, 'w') as f:  # pylint: disable=unspecified-encoding,consider-using-with
    result = subprocess.run(['flawfinder'] + args, stdout=f)

with open(output) as f:  # pylint: disable=unspecified-encoding,consider-using-with
    sys.stdout.write(f.read())

sys.exit(result.returncode)
