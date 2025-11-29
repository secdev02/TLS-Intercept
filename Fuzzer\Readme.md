[FUZZER_GUIDE.md](https://github.com/user-attachments/files/23836320/FUZZER_GUIDE.md)
# ECC Certificate Fuzzer - Usage Guide

## Overview
This PowerShell script performs systematic fuzzing of ASN.1 length bytes in X.509 certificates. It automatically finds all length fields, mutates them, attempts to parse the modified certificates, and logs all results including crashes.

## Features

- **Automatic Length Field Discovery** - Finds all ASN.1 length bytes in the certificate
- **Multiple Fuzzing Modes** - Sequential, Random, Boundary, or All
- **Comprehensive Logging** - Detailed logs of every mutation and result
- **Crash Detection** - Saves certificates that cause crashes
- **Statistics Tracking** - Success/fail rates, error types, unique offsets
- **Flexible Input** - From file, Windows store, or generate new

## Parameters

### Input Sources (pick one)
- `-InputCert` - Path to certificate file to fuzz
- `-Thumbprint` - Certificate thumbprint from Windows store
- `-SubjectPattern` - Subject pattern to search (e.g., `*.google.com`)
- `-GenerateNew` - Generate a fresh ECC certificate for fuzzing

### Fuzzing Configuration
- `-FuzzMode` - Fuzzing strategy:
  - `Sequential` - Try all 256 possible byte values (0x00-0xFF)
  - `Random` - 50 random values per offset
  - `Boundary` - Focus on boundary values (0x00, 0x7F, 0x80, 0xFF, etc.)
  - `All` - Boundary values + random sampling (default)
  
- `-MaxIterations` - Maximum number of fuzzing iterations (default: 1000)
- `-OutputDir` - Directory for results (default: "fuzz-results")
- `-VerboseLogging` - Show all mutations in console (default: errors only)

### Certificate Generation (when using -GenerateNew)
- `-SubjectName` - Subject name for generated cert (default: "CN=fuzz-target")

### Certificate Store (when using -Thumbprint or -SubjectPattern)
- `-StoreLocation` - "CurrentUser" or "LocalMachine" (default: "CurrentUser")
- `-StoreName` - Store name (default: "My")

## Usage Examples

### 1. Generate and Fuzz a New Certificate (Quickest Start)

```powershell
# Generate new cert and fuzz with boundary values
.\ecc-cert-fuzzer.ps1 -GenerateNew

# Generate and fuzz with ALL possible byte values (comprehensive)
.\ecc-cert-fuzzer.ps1 -GenerateNew -FuzzMode Sequential

# Generate with custom subject
.\ecc-cert-fuzzer.ps1 -GenerateNew -SubjectName "CN=my-test-cert" -FuzzMode All
```

### 2. Fuzz an Existing Certificate File

```powershell
# Fuzz a certificate file
.\ecc-cert-fuzzer.ps1 -InputCert "C:\certs\example.cer"

# Fuzz with random values only
.\ecc-cert-fuzzer.ps1 -InputCert "example.cer" -FuzzMode Random

# Limit to 500 iterations
.\ecc-cert-fuzzer.ps1 -InputCert "example.cer" -MaxIterations 500
```

### 3. Fuzz Certificate from Windows Store

```powershell
# By thumbprint
.\ecc-cert-fuzzer.ps1 -Thumbprint "A1B2C3D4E5F6..."

# By subject pattern
.\ecc-cert-fuzzer.ps1 -SubjectPattern "*localhost*"

# From LocalMachine store
.\ecc-cert-fuzzer.ps1 -SubjectPattern "*.google.com" -StoreLocation LocalMachine -StoreName Root
```

### 4. Advanced Fuzzing Campaigns

```powershell
# Exhaustive fuzzing with verbose output
.\ecc-cert-fuzzer.ps1 -GenerateNew -FuzzMode Sequential -MaxIterations 10000 -VerboseLogging

# Quick boundary value test
.\ecc-cert-fuzzer.ps1 -InputCert "test.cer" -FuzzMode Boundary -MaxIterations 100

# Custom output directory
.\ecc-cert-fuzzer.ps1 -GenerateNew -OutputDir "C:\fuzzing\campaign-001"
```

## Output Files

The fuzzer creates the following output structure:

```
fuzz-results/
├── fuzz_log_20241129_143022.txt          # Detailed iteration log
├── fuzz_summary_20241129_143022.txt      # Summary statistics
└── crashes/                               # Certificates that caused crashes
    ├── crash_42_offset150.cer
    ├── crash_87_offset312.cer
    └── crash_153_offset89.cer
```

### Log File Format

Each iteration is logged with:
```
[2024-11-29 14:30:22.145] [INFO] ITERATION 42: OFFSET=150 TAG=0x30 ORIG=0x82 NEW=0xFF
[2024-11-29 14:30:22.167] [ERROR]   RESULT: FAILED - CryptographicException - ASN1 corrupted data
```

### Summary Report

The summary includes:
- Execution time
- Total iterations
- Success/failure rates
- Unique offsets fuzzed
- Error types encountered
- Crash count
- File locations

## Fuzzing Modes Explained

### Sequential Mode
- Tests every possible byte value (0-255)
- Most comprehensive but slowest
- Best for thorough security testing
- Example: For each length byte, try 0x00, 0x01, 0x02, ..., 0xFE, 0xFF

### Random Mode
- 50 random values per offset
- Fast but less coverage
- Good for quick testing
- May miss edge cases

### Boundary Mode
- Focuses on interesting values:
  - 0x00 - Zero length
  - 0x7F - Maximum short form
  - 0x80 - Indefinite length / long form marker
  - 0x81-0x84 - Long form indicators
  - 0xFF - Maximum value
  - Original value ±1
- Fast and effective
- Catches most common parsing bugs

### All Mode (Default)
- Boundary values + 20 random samples
- Good balance of speed and coverage
- Recommended for general use

## Interpreting Results

### Success Rate
```
SUCCESSFUL PARSES: 234 (23.4%)
FAILED PARSES:     766 (76.6%)
```
- High success rate (>50%) = Robust parser
- Low success rate (<20%) = Strict parser (good for security)

### Error Types
Common errors you'll see:
- `CryptographicException` - ASN.1 parsing failed (expected)
- `ArgumentException` - Invalid certificate format
- `FormatException` - Data format issues
- `AccessViolationException` - **CRITICAL** - Potential security issue

### Crashes
Files saved to `crashes/` directory indicate:
- Parser crashed or threw severe exception
- Potential security vulnerability
- Memory corruption issues
- Should be investigated further

## Example Workflow

```powershell
# Step 1: Quick test with boundary values
.\ecc-cert-fuzzer.ps1 -GenerateNew -FuzzMode Boundary

# Step 2: Review summary
Get-Content .\fuzz-results\fuzz_summary_*.txt

# Step 3: If crashes found, run comprehensive test
.\ecc-cert-fuzzer.ps1 -GenerateNew -FuzzMode Sequential -MaxIterations 5000

# Step 4: Examine crash files
Get-ChildItem .\fuzz-results\crashes\

# Step 5: Test specific crash with parser
.\ecc-cert-asn-parser.ps1 -ParseOnly -ParseFile ".\fuzz-results\crashes\crash_42_offset150.cer"
```

## Performance Tips

1. **Start Small** - Use Boundary mode first (fastest)
2. **Increase Gradually** - Move to All, then Sequential if needed
3. **Limit Iterations** - Use `-MaxIterations` to control runtime
4. **Disable Verbose** - Don't use `-VerboseLogging` for large campaigns
5. **SSD Storage** - Use SSD for output directory (many small writes)

## Security Testing Best Practices

1. **Test Multiple Certificates** - Different issuers, key types, extensions
2. **Document Crashes** - Always investigate saved crash files
3. **Reproduce Issues** - Re-run with the same crash file to confirm
4. **Test Parsers** - Fuzz different certificate parsers (OpenSSL, BoringSSL, etc.)
5. **Combine with Other Fuzzing** - Also fuzz tag bytes, content, etc.

## Integration with Main Parser

Use the fuzzer with the ASN.1 parser for detailed analysis:

```powershell
# Generate and fuzz
.\ecc-cert-fuzzer.ps1 -GenerateNew -FuzzMode Boundary

# Analyze a crash
.\ecc-cert-asn-parser.ps1 -ParseOnly -ParseFile ".\fuzz-results\crashes\crash_42_offset150.cer"
```

## Common Scenarios

### Scenario 1: Test a Production Certificate
```powershell
# Export from browser, then fuzz
.\ecc-cert-fuzzer.ps1 -InputCert "C:\Downloads\google-com.cer" -FuzzMode All
```

### Scenario 2: Regression Testing
```powershell
# Fuzz with known-good certificate
.\ecc-cert-fuzzer.ps1 -InputCert "baseline.cer" -FuzzMode Sequential -OutputDir "regression-test"
```

### Scenario 3: Quick Smoke Test
```powershell
# Fast test for obvious bugs
.\ecc-cert-fuzzer.ps1 -GenerateNew -FuzzMode Boundary -MaxIterations 50
```

## Troubleshooting

**"FOUND 0 LENGTH FIELDS"**
- Certificate file may be corrupted
- Try generating a new certificate with `-GenerateNew`

**Fuzzer runs too slowly**
- Use `-FuzzMode Boundary` or `-FuzzMode Random`
- Reduce `-MaxIterations`
- Remove `-VerboseLogging`

**Too many crashes**
- This might indicate a genuine parser bug
- Review crash files manually
- Test with different certificate parsers

**Out of disk space**
- Crashes directory can grow large
- Clean up old crash files
- Use `-MaxIterations` to limit campaign size
