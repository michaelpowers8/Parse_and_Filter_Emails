# Email Processing Toolkit

This repository contains Python scripts for processing and analyzing email data in `.eml` format. The tools help parse email content, extract metadata, and identify unique email subsets.

## Scripts Overview

### 1. Parse_Emails.py

A comprehensive email parser that processes `.eml` files and extracts:
- Email metadata (date, sender, recipients)
- Subject lines
- Email bodies (both plain text and HTML)
- Generates SHA-256 hashes of email content

**Key Features:**
- Handles multiple email directories
- Logs all operations with an XML logger
- Outputs parsed data in JSON format
- Preserves email structure while extracting clean text

**Dependencies:**
- pandas
- BeautifulSoup
- mailparser
- email (Python standard library)
- hashlib (Python standard library)

### 2. find_email_subsets.py

An advanced email analysis tool that:
- Identifies duplicate or near-duplicate emails
- Cleans email content by removing links and email addresses
- Uses similarity matching to find email subsets
- Optimized for performance with large datasets

**Key Features:**
- Length-based indexing for efficient comparison
- Sequence matching for similarity detection
- Configurable similarity threshold
- Outputs cleaned data in both JSON and CSV formats

**Dependencies:**
- pandas
- numpy
- tqdm
- difflib (Python standard library)
- re (Python standard library)

## Configuration

Both scripts require configuration files:

### Parse_Emails.py
Requires `Parse_Emails_Configuration.json` with:
```json
{
  "Email_Directories": ["path/to/eml/files"],
  "Parsed_Email_Save_Folder": "output/path",
  "Restart_Email_Parsing": true
}
```

### find_email_subsets.py
Requires `find_email_subset_configuration.json` with:
```json
{
  "Original_Data_Path": "path/to/parsed/data.json"
}
```

## Usage

1. First run `Parse_Emails.py` to process your `.eml` files:
```bash
python Parse_Emails.py
```

2. Then run `find_email_subsets.py` to analyze the results:
```bash
python find_email_subsets.py
```

## Output

- `Parse_Emails.py` generates:
  - JSON files with parsed email data
  - Text files with extracted email content
  - XML logs of the parsing process

- `find_email_subsets.py` generates:
  - `Cleaned_Email_Data.json` - Unique emails in JSON format
  - `Cleaned_Email_Data.csv` - Unique emails in CSV format
  - XML logs of the analysis process

## Performance Notes

- Both scripts are optimized for processing large volumes of emails
- Memory usage scales with input size
- Progress is logged and displayed in console
- Intermediate results are saved periodically

## Error Handling

Comprehensive error handling and logging is implemented:
- All errors are logged with stack traces
- Processing continues after non-critical errors
- Critical errors terminate execution with clear messages