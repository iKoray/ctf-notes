import re
import csv

# Read the raw TCP stream dump
with open("raw_stream.txt", "r") as infile:
    data = infile.read()

# Clean up weird spacing, dots, and noise
data = data.replace('\x00', '')  # Remove null bytes
data = re.sub(r'\.{2,}', '\t', data)  # Replace dots with tabs for easier split
data = re.sub(r'\s+', '\t', data)  # Normalize spaces into tabs too

# Now split into lines
lines = data.strip().splitlines()

# Extract headers if they exist
header_line = lines[0]
headers = [h.strip() for h in header_line.split('\t') if h]

# Prepare output
extracted_rows = []

for line in lines[1:]:
    fields = [field.strip() for field in line.split('\t') if field]
    if len(fields) >= 3:  # basic sanity check: id, upload_date, filename at least
        extracted_rows.append(fields)

# Write clean CSV output
with open("clean_metadata.csv", "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(headers)
    for row in extracted_rows:
        writer.writerow(row)

print(f"[+] Extraction complete. Saved to clean_metadata.csv")
