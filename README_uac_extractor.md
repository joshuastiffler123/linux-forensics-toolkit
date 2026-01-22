# UAC Collection Extractor

A tool for extracting UAC (Unix-like Artifacts Collector) tarballs from ZIP archives, including deeply nested ZIPs.

## Features

- **Nested ZIP Support**: Handles ZIP files inside ZIP files (unlimited depth)
- **Multiple TAR Formats**: Supports `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`
- **Tracking**: Maps extracted files to their source ZIPs in a CSV
- **Cleanup**: Optionally removes source ZIPs after successful extraction
- **Dry Run**: Preview what would be extracted without making changes
- **Duplicate Handling**: Automatically renames duplicates with counter suffix

## Requirements

- **Python 3.6+** (standard library only - no pip install needed)

## Installation

No installation required. Simply download and run:

```bash
# Make executable (Linux/Mac)
chmod +x uac_extractor.py
```

## Usage

### Basic Usage

```bash
# Extract all UAC tarballs from ZIPs in a directory
python uac_extractor.py C:\ZipArchives C:\ExtractedUAC

# Linux/Mac
python uac_extractor.py ./zip_archives ./extracted_uac
```

### Command Line Options

```bash
python uac_extractor.py <search_directory> <output_directory> [options]
```

| Argument | Description |
|----------|-------------|
| `search_directory` | Directory to recursively search for ZIP files |
| `output_directory` | Directory to extract UAC files to |

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview extraction without making changes |
| `--keep-zips` | Don't delete source ZIP files after extraction |
| `-v`, `--verbose` | Show detailed contents of each ZIP file |

### Examples

```bash
# Preview what would be extracted (dry run)
python uac_extractor.py C:\Evidence C:\Output --dry-run

# Extract but keep original ZIP files
python uac_extractor.py C:\Evidence C:\Output --keep-zips

# Verbose mode - show ZIP contents
python uac_extractor.py C:\Evidence C:\Output --verbose

# Combine options
python uac_extractor.py C:\Evidence C:\Output --dry-run --verbose
```

## Output

### Extracted Files

UAC tarballs are extracted to the output directory with their original names:
```
C:\Output\
├── hostname1-C12345-F0001.tar
├── hostname2-C12345-F0002.tar
├── hostname3-C67890-F0001.tar.gz
└── uac_mapping_20241217_143022.csv
```

### Mapping CSV

A CSV file is generated mapping each extracted file to its source:

| Column | Description |
|--------|-------------|
| `UAC_Filename` | Name of extracted TAR file |
| `Source_ZIP` | Top-level ZIP file name |
| `Source_ZIP_Path` | Full path to source ZIP |
| `Nested_Path` | Path through nested ZIPs (e.g., `outer.zip -> inner.zip -> file.tar`) |
| `Extracted_To` | Full path where file was extracted |
| `Timestamp` | Extraction timestamp |
| `Size_Bytes` | File size in bytes |
| `Success` | Whether extraction succeeded |
| `Error_Message` | Error details if failed |

## Workflow

### Typical Forensic Workflow

```bash
# Step 1: Extract UAC tarballs from evidence ZIPs
python uac_extractor.py C:\Evidence\ZipArchives C:\Evidence\ExtractedUAC --keep-zips

# Step 2: Generate login timelines from extracted tarballs
python linux_login_timeline.py --batch C:\Evidence\ExtractedUAC -o C:\Evidence\Timelines

# Step 3: Sort IZE files by hostname
python ize_sorter.py C:\Evidence\ZipArchives C:\Mappings\hosts.csv C:\Evidence\SortedIZE
```

### Handling Large Evidence Sets

```bash
# First, do a dry run to see what will be extracted
python uac_extractor.py D:\CaseEvidence D:\Extracted --dry-run --verbose

# Review the output, then run for real
python uac_extractor.py D:\CaseEvidence D:\Extracted --keep-zips
```

## Console Output

```
============================================================
  UAC Collection Extractor
============================================================

Search Directory: C:\Evidence\ZipArchives
Output Directory: C:\Evidence\ExtractedUAC
TAR Extensions: .tar, .tar.gz, .tgz, .tar.bz2
Dry Run: False
Keep ZIPs: True
Verbose: False

Scanning for ZIP files...
Found 15 top-level ZIP file(s)

Processing: C:\Evidence\ZipArchives\case001.zip
  Found 3 UAC/TAR file(s)
  ✓ Extracted: server01-C12345-F0001.tar (45.2 MB)
  ✓ Extracted: server02-C12345-F0002.tar (32.1 MB)
  ✓ Extracted: workstation01-C12345-F0003.tar (18.7 MB)
  Found 1 nested ZIP(s)
  Entering nested ZIP: inner_archive.zip
    Found 2 UAC/TAR file(s)
    ✓ Extracted: laptop01-C12345-F0004.tar (12.3 MB)
    ✓ Extracted: laptop02-C12345-F0005.tar (8.9 MB)

...

Mapping CSV written to: C:\Evidence\ExtractedUAC\uac_mapping_20241217_143022.csv

============================================================
  Extraction Summary
============================================================

  Top-level ZIPs scanned: 15
  Nested ZIPs scanned:    8
  UAC files found:        47
  UAC files extracted:    47
  Total data extracted:   1.2 GB
  ZIP files deleted:      0
```

## Security

This tool follows OWASP Top 10 security guidelines:
- **A03/A08**: Zip slip prevention - validates extraction paths
- **A05**: Proper exception handling with specific exception types

## Supported Archive Formats

| Extension | Description |
|-----------|-------------|
| `.tar` | Uncompressed TAR archive |
| `.tar.gz` | Gzip-compressed TAR archive |
| `.tgz` | Gzip-compressed TAR archive (alternate extension) |
| `.tar.bz2` | Bzip2-compressed TAR archive |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No TAR files found | Use `--verbose` to see ZIP contents |
| Corrupted ZIP | Tool will report error and continue with other files |
| Permission denied | Run with elevated privileges or check file permissions |
| Disk space | Check available space before extracting large archives |
| Duplicate filenames | Files are automatically renamed with `_1`, `_2` suffix |

## Error Handling

- Corrupted ZIPs are logged and skipped
- Failed extractions are recorded in the mapping CSV with error details
- Processing continues even if individual files fail
- Summary shows total errors at the end

## License

Internal forensics tool. Handle evidence data according to your organization's policies.


