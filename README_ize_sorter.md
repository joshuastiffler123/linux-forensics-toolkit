# IZE & UAC Collection Sorter

A tool for sorting Kaseya `.IZE` collection files and UAC `.TAR` files into organized folders based on hostname-to-product mappings from a CSV file.

## Features

- **Multi-Format Support**: Sorts both `.IZE` (Kaseya) and `.TAR` (UAC) files
- **Nested ZIP Extraction**: Finds collections inside ZIP files (any depth)
- **Fuzzy Matching**: Matches filenames to hostnames using intelligent scoring
- **Client ID Extraction**: Extracts Client IDs from filenames (C###-F pattern)
- **Duplicate Handling**: Keeps the larger file when duplicates are found
- **Folder Sanitization**: Removes invalid characters from folder names
- **Detailed Logging**: Generates log files and results CSV

## Requirements

- **Python 3.6+** (standard library only - no pip install needed)

## Installation

No installation required. Simply download and run:

```bash
# Make executable (Linux/Mac)
chmod +x ize_sorter.py
```

## Usage

### Basic Usage

```bash
python ize_sorter.py <search_path> <csv_file> <output_dir> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `search_path` | Directory to search for collections (recursively, including ZIPs) |
| `csv_file` | CSV file with hostname-to-product mappings |
| `output_dir` | Output directory where sorted folders will be created |

### Options

| Option | Description |
|--------|-------------|
| `--threshold` | Minimum match score (0-100) to consider a match (default: 70) |
| `--dry-run` | Preview matches without copying files |
| `--debug` | Show detailed debug info about ZIP contents |
| `--test-matching` | Test matching logic and show extraction details |

### Examples

```bash
# Basic sorting
python ize_sorter.py C:\ZipArchives hosts.csv C:\SortedOutput

# Lower threshold for more matches
python ize_sorter.py ./source mapping.csv ./output --threshold 60

# Preview what would be sorted (dry run)
python ize_sorter.py ./source mapping.csv ./output --dry-run

# Test matching without copying
python ize_sorter.py ./source mapping.csv ./output --test-matching

# Debug mode to see ZIP contents
python ize_sorter.py ./source mapping.csv ./output --debug
```

## CSV File Format

The CSV file maps hostnames to destination folders:

| Column A | Column B |
|----------|----------|
| Hostname keyword | Product/Folder name |

### Example CSV

```csv
Hostname,Product
SERVER-DC01,Kaseya_Backup
SERVER-DC02,Kaseya_Backup
SQL-SERVER,Kaseya_Monitoring
WORKSTATION-HR,HR_Department
LAPTOP-SALES,Sales_Team
```

### CSV Rules

- **Column A**: The hostname or keyword to search for in filenames
- **Column B**: The destination folder name for matched files
- First row can be a header (auto-detected) or data
- Empty rows are skipped

## Matching Logic

The tool uses intelligent fuzzy matching to find the best hostname match:

| Match Type | Score | Description |
|------------|-------|-------------|
| Exact Match | 100% | Filename exactly matches hostname |
| Substring | 90-100% | Hostname found within filename |
| Reverse Substring | 88% | Filename found within hostname |
| Normalized | 85% | Match after removing separators (`_`, `-`, `.`) |
| Word Match | 80% | All words from hostname found in filename |
| Partial Word | 70-80% | Some words match |
| Fuzzy Ratio | Variable | Sequence similarity fallback |

### Client ID Extraction

The tool extracts Client IDs from filenames matching these patterns:

```
Pattern: [computername]-C[clientid]-F####
Examples:
  SERVER-DC01-C12345-F0001.tar → Client ID: C12345
  WORKSTATION-HR-C98765-F0002.ize → Client ID: C98765
```

## Output Structure

```
C:\SortedOutput\
├── Kaseya_Backup\
│   ├── SERVER-DC01.ize
│   └── SERVER-DC02.ize
├── Kaseya_Monitoring\
│   └── SQL-SERVER.ize
├── HR_Department\
│   └── WORKSTATION-HR-C12345-F0001.tar
├── ize_sorter_log_20241217_143022.txt
└── ize_sorter_results_20241217_143022.csv
```

## Output Files

### Results CSV

| Column | Description |
|--------|-------------|
| `Filename` | Name of the collection file |
| `File Type` | IZE or UAC |
| `Client ID` | Extracted Client ID (if present) |
| `Source ZIP` | ZIP file the collection was found in |
| `File Size (bytes)` | File size |
| `Status` | MATCHED, UNMATCHED, DUPLICATE_REPLACED, DUPLICATE_SKIPPED |
| `Destination Folder` | Where the file was sorted to |
| `Matched Hostname` | Hostname from CSV that matched |
| `Match Score` | Matching score percentage |
| `Match Type` | Type of match (EXACT, SUBSTRING, etc.) |
| `Destination Path` | Full path to sorted file |
| `Notes` | Additional information |

### Log File

Detailed log including:
- Configuration used
- All CSV mappings loaded
- Each file's matching analysis
- Duplicate handling decisions
- Errors and warnings
- Final statistics

## Console Output

```
╔═══════════════════════════════════════════════════════════════╗
║                              SUMMARY                           ║
╠═══════════════════════════════════════════════════════════════╣
║                                                                ║
║   Total .IZE files found:     47                               ║
║   Successfully sorted:        42 (89.4%)                       ║
║   Duplicates replaced:        3                                ║
║   Unmatched:                  5                                ║
║                                                                ║
║   Errors:                     0                                ║
║   Warnings:                   2                                ║
║                                                                ║
╚═══════════════════════════════════════════════════════════════╝

✓ COMPLETE

  Sorted files:  C:\SortedOutput
  Log file:      ize_sorter_log_20241217_143022.txt
  Results CSV:   ize_sorter_results_20241217_143022.csv
```

## Duplicate Handling

When the same filename would be sorted to the same folder:

1. **Compare file sizes**
2. **Keep the larger file** (more complete collection)
3. **Log the decision** in both log file and CSV

## Workflow Example

```bash
# Step 1: Extract UAC tarballs from evidence ZIPs (optional)
python uac_extractor.py C:\Evidence C:\ExtractedUAC --keep-zips

# Step 2: Create your hostname mapping CSV
# (Create hosts.csv with hostname -> product mappings)

# Step 3: Test the matching before sorting
python ize_sorter.py C:\Evidence hosts.csv C:\Sorted --test-matching

# Step 4: Do a dry run to preview
python ize_sorter.py C:\Evidence hosts.csv C:\Sorted --dry-run

# Step 5: Run the actual sort
python ize_sorter.py C:\Evidence hosts.csv C:\Sorted

# Step 6: Generate timelines from UAC files
python linux_login_timeline.py --batch C:\Sorted -o C:\Timelines
```

## Security

This tool follows OWASP Top 10 security guidelines:
- **A03/A08**: Zip slip prevention during extraction
- **A05**: Proper exception handling
- **A08**: Output path validation before file operations

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Low match rate | Lower `--threshold` value (try 50-60) |
| Wrong matches | Increase `--threshold` or refine CSV hostnames |
| Invalid folder names | Tool auto-sanitizes (removes `:`, `?`, `*`, etc.) |
| Missing files | Use `--debug` to see ZIP contents |
| Duplicates | Check log for duplicate handling decisions |

### Common Folder Name Characters Sanitized

These characters are replaced with `_`:
- `\` `/` `:` `*` `?` `"` `<` `>` `|`

## Tips

1. **Start with `--test-matching`** to verify extraction and matching logic
2. **Use `--dry-run`** before actual sorting to preview results
3. **Check unmatched files** - they may need hostname entries added to CSV
4. **Review the results CSV** for a complete audit trail
5. **Lower threshold** if you have partial hostnames in the CSV

## License

Internal forensics tool. Handle evidence data according to your organization's policies.


