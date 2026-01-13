// Test for console output sanitization
// This file demonstrates the sanitization features

package main

import (
	"fmt"
	"testing"
)

func TestSanitizeForConsole(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Bell character (beep)",
			input:    "Hello\x07World",
			expected: "Hello\\x07World",
		},
		{
			name:     "Multiple control characters",
			input:    "Test\x00\x01\x02\x03Data",
			expected: "Test\\x00\\x01\\x02\\x03Data",
		},
		{
			name:     "Preserve newlines and tabs",
			input:    "Line1\nLine2\tTabbed",
			expected: "Line1\nLine2\tTabbed",
		},
		{
			name:     "Preserve printable ASCII",
			input:    "Normal text 123 !@#$%",
			expected: "Normal text 123 !@#$%",
		},
		{
			name:     "Preserve Unicode",
			input:    "Hello 世界 مرحبا",
			expected: "Hello 世界 مرحبا",
		},
		{
			name:     "Mixed control and printable",
			input:    "Start\x07Middle\x1BEnd",
			expected: "Start\\x07Middle\\x1bEnd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForConsole(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeForConsole() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "Plain text",
			input:    []byte("This is normal text"),
			expected: false,
		},
		{
			name:     "JSON data",
			input:    []byte(`{"key": "value", "number": 123}`),
			expected: false,
		},
		{
			name:     "Binary with null bytes",
			input:    []byte{0x00, 0x01, 0x02, 0x03, 0x89, 0x50, 0x4E, 0x47},
			expected: true,
		},
		{
			name:     "PNG header",
			input:    []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expected: true,
		},
		{
			name:     "Empty content",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "Text with newlines",
			input:    []byte("Line1\nLine2\nLine3\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinaryContent(tt.input)
			if result != tt.expected {
				t.Errorf("isBinaryContent() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Example demonstrating the issue
func ExampleControlCharacterIssue() {
	// Without sanitization, this would cause terminal to beep
	badString := "Alert! \x07 Something happened"
	
	// With sanitization
	cleanString := sanitizeForConsole(badString)
	
	fmt.Println("Original would beep, sanitized shows:")
	fmt.Println(cleanString)
	// Output: Alert! \x07 Something happened
}

// Example of binary detection
func ExampleBinaryDetection() {
	// Text data - not binary
	textData := []byte("This is plain text with some data")
	fmt.Printf("Text is binary: %v\n", isBinaryContent(textData))
	
	// Binary data (PNG header)
	binaryData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	fmt.Printf("PNG header is binary: %v\n", isBinaryContent(binaryData))
	
	// Output:
	// Text is binary: false
	// PNG header is binary: true
}
