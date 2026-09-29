#!/usr/bin/env python3
import csv
import sys

rows = list(csv.reader(open(sys.argv[1], encoding="utf-8")))
print("| " + " | ".join(rows[0]) + " |")
print("|" + "---|" * len(rows[0]))
for row in rows[1:]:
    print("| " + " | ".join(row) + " |")
