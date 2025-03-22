#!/usr/bin/env python3
"""
Error Usage Analyzer

This script analyzes the codebase to identify unused error variants in error enums.
It helps maintain clean error handling by finding errors that can be removed.

Usage:
    python scripts/analyze_error_usage.py

Output:
    - List of potentially unused error variants
    - Suggestions for error normalization
"""

import os
import re
import sys
from collections import defaultdict, Counter
from pathlib import Path

# Configuration
SRC_DIR = Path("src")
ERROR_MODULE_PATHS = [
    Path("src/errors.rs"),
    Path("src/crypto/errors.rs"),
]
EXCLUDE_DIRS = [
    Path("src/tests"),
    Path("src/crypto/tests"),
]

# Regex patterns
ERROR_ENUM_PATTERN = re.compile(r"pub enum (\w+Error)\s*\{([^}]+)\}")
ERROR_VARIANT_PATTERN = re.compile(r"^\s*(\w+)(?:\([^)]*\))?,?\s*(?://.*)?$", re.MULTILINE)
ERROR_USAGE_PATTERN = re.compile(r"(\w+Error)::(\w+)")

def find_error_enums():
    """Find all error enum definitions and their variants"""
    error_enums = {}
    
    for path in ERROR_MODULE_PATHS:
        if not path.exists():
            print(f"Warning: Error module not found at {path}")
            continue
            
        with open(path, 'r') as file:
            content = file.read()
            for enum_match in ERROR_ENUM_PATTERN.finditer(content):
                enum_name = enum_match.group(1)
                enum_body = enum_match.group(2)
                
                variants = []
                for variant_match in ERROR_VARIANT_PATTERN.finditer(enum_body):
                    variant_name = variant_match.group(1)
                    variants.append(variant_name)
                
                error_enums[enum_name] = variants
    
    return error_enums

def find_error_usages():
    """Find all usages of error variants in the codebase"""
    usages = defaultdict(set)
    
    for root, dirs, files in os.walk(SRC_DIR):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if Path(root) / d not in EXCLUDE_DIRS]
        
        for file in files:
            if file.endswith(".rs"):
                file_path = Path(root) / file
                with open(file_path, 'r') as f:
                    content = f.read()
                    for match in ERROR_USAGE_PATTERN.finditer(content):
                        enum_name = match.group(1)
                        variant_name = match.group(2)
                        usages[enum_name].add(variant_name)
    
    return usages

def analyze_error_normalization():
    """Analyze error message normalization patterns"""
    error_messages = []
    
    for root, dirs, files in os.walk(SRC_DIR):
        dirs[:] = [d for d in dirs if Path(root) / d not in EXCLUDE_DIRS]
        
        for file in files:
            if file.endswith(".rs"):
                file_path = Path(root) / file
                with open(file_path, 'r') as f:
                    content = f.read()
                    # Find error message strings in Err(...) patterns
                    for line in content.split('\n'):
                        if "Err(" in line and "\"" in line:
                            error_messages.append(line.strip())
    
    # Count common patterns in error messages
    words = Counter()
    for msg in error_messages:
        # Extract the message part
        if "\"" in msg:
            parts = msg.split("\"")
            if len(parts) >= 3:
                message = parts[1]
                # Count common words
                for word in message.split():
                    if len(word) > 3:  # Skip small words
                        words[word.lower()] += 1
    
    return words.most_common(20)

def main():
    print("Analyzing error variants usage...\n")
    
    # Find error enums and their variants
    error_enums = find_error_enums()
    print(f"Found {len(error_enums)} error enums:")
    for enum_name, variants in error_enums.items():
        print(f"  - {enum_name}: {len(variants)} variants")
    print()
    
    # Find error usages
    error_usages = find_error_usages()
    
    # Find unused variants
    unused_variants = {}
    for enum_name, variants in error_enums.items():
        used_variants = error_usages.get(enum_name, set())
        unused = [v for v in variants if v not in used_variants]
        if unused:
            unused_variants[enum_name] = unused
    
    # Print results
    if unused_variants:
        print("Potentially unused error variants:")
        for enum_name, variants in unused_variants.items():
            print(f"  - {enum_name}:")
            for variant in variants:
                print(f"    - {variant}")
        print()
        print("Note: These variants might be used indirectly (e.g., through conversion traits).")
        print("Manual verification is recommended before removal.")
    else:
        print("No unused error variants found.")
    
    print("\nAnalyzing error message patterns...")
    common_patterns = analyze_error_normalization()
    print("\nMost common terms in error messages:")
    for term, count in common_patterns:
        print(f"  - '{term}': {count} occurrences")
    
    print("\nRecommendations:")
    print("  1. Remove unused error variants if confirmed unused")
    print("  2. Normalize error messages for consistency")
    print("  3. Consider using helper methods for common error patterns")

if __name__ == "__main__":
    main() 