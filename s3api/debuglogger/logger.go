// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package debuglogger

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	reset      = "\033[0m"
	green      = "\033[32m"
	yellow     = "\033[33m"
	blue       = "\033[34m"
	borderChar = "─"
	boxWidth   = 120
)

// Logs http request details: headers, body, params, query args
func LogFiberRequestDetails(ctx *fiber.Ctx) {
	// Log the full request url
	fullURL := ctx.Protocol() + "://" + ctx.Hostname() + ctx.OriginalURL()
	fmt.Printf("%s[URL]: %s%s\n", green, fullURL, reset)

	// log request headers
	wrapInBox(green, "REQUEST HEADERS", boxWidth, func() {
		ctx.Request().Header.VisitAll(func(key, value []byte) {
			printWrappedLine(yellow, string(key), string(value))
		})
	})
	// skip request body log for PutObject and UploadPart
	skipBodyLog := isLargeDataAction(ctx)
	if !skipBodyLog {
		body := ctx.Request().Body()
		if len(body) != 0 {
			printBoxTitleLine(blue, "REQUEST BODY", boxWidth, false)
			prettyBody := prettyPrintXML(body)
			fmt.Printf("%s%s%s\n", blue, prettyBody, reset)
			printHorizontalBorder(blue, boxWidth, false)
		}
	}

	if ctx.Request().URI().QueryArgs().Len() != 0 {
		ctx.Request().URI().QueryArgs().VisitAll(func(key, val []byte) {
			log.Printf("%s: %s", key, val)
		})
	}
}

// Logs http response details: body, headers
func LogFiberResponseDetails(ctx *fiber.Ctx) {
	wrapInBox(green, "RESPONSE HEADERS", boxWidth, func() {
		ctx.Response().Header.VisitAll(func(key, value []byte) {
			printWrappedLine(yellow, string(key), string(value))
		})
	})

	_, ok := ctx.Locals("skip-res-body-log").(bool)
	if !ok {
		body := ctx.Response().Body()
		if len(body) != 0 {
			printBoxTitleLine(blue, "RESPONSE BODY", boxWidth, false)
			prettyBody := prettyPrintXML(body)
			fmt.Printf("%s%s%s\n", blue, prettyBody, reset)
			printHorizontalBorder(blue, boxWidth, false)
		}
	}
}

// Logf is the same as 'fmt.Printf' with debug prefix,
// a color added and '\n' at the end
func Logf(format string, v ...any) {
	debugPrefix := "[DEBUG]: "
	fmt.Printf(yellow+debugPrefix+format+reset+"\n", v...)
}

// prettyPrintXML takes raw XML input and returns a formatted (pretty-printed) version.
func prettyPrintXML(input []byte) string {
	b := &bytes.Buffer{}
	decoder := xml.NewDecoder(bytes.NewReader(input))
	encoder := xml.NewEncoder(b)
	encoder.Indent("", "  ")

	var depth int
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			encoder.Flush()
			return b.String()
		}
		if err != nil {
			// Return the raw input if decoding fails
			return string(input)
		}

		switch t := token.(type) {
		case xml.StartElement:
			if depth > 0 {
				// Strip namespace from tag name
				t.Name.Space = ""

				// Filter out xmlns attributes to make it more readable
				newAttrs := make([]xml.Attr, 0, len(t.Attr))
				for _, attr := range t.Attr {
					if !(attr.Name.Space == "" && attr.Name.Local == "xmlns") {
						newAttrs = append(newAttrs, attr)
					}
				}
				t.Attr = newAttrs
			}
			depth++
			err = encoder.EncodeToken(t)
		case xml.EndElement:
			if depth > 1 {
				t.Name.Space = ""
			}
			depth--
			err = encoder.EncodeToken(t)
		default:
			err = encoder.EncodeToken(t)
		}

		if err != nil {
			// Return the raw input if decoding fails
			return string(input)
		}
	}
}

// Prints out box title either with closing characters or not:  "┌", "┐"
// e.g ┌────────────────[ RESPONSE HEADERS ]────────────────┐
func printBoxTitleLine(color, title string, length int, closing bool) {
	leftCorner, rightCorner := "┌", "┐"

	if !closing {
		leftCorner, rightCorner = borderChar, borderChar
	}

	// Calculate how many border characters are needed
	titleFormatted := fmt.Sprintf("[ %s ]", title)
	borderSpace := length - len(titleFormatted) - 2 // 2 for corners
	leftLen := borderSpace / 2
	rightLen := borderSpace - leftLen

	// Build the line
	line := leftCorner +
		strings.Repeat(borderChar, leftLen) +
		titleFormatted +
		strings.Repeat(borderChar, rightLen) +
		rightCorner

	fmt.Println(color + line + reset)
}

// Prints out a horizontal line either with closing characters or not: "└", "┘"
func printHorizontalBorder(color string, length int, closing bool) {
	leftCorner, rightCorner := "└", "┘"
	if !closing {
		leftCorner, rightCorner = borderChar, borderChar
	}

	line := leftCorner + strings.Repeat(borderChar, length-2) + rightCorner + reset
	fmt.Println(color + line)
}

// wrapInBox wraps the output of a function call (fn) inside a styled box with a title.
func wrapInBox(color, title string, length int, fn func()) {
	printBoxTitleLine(color, title, length, true)
	fn()
	printHorizontalBorder(color, length, true)
}

// returns the provided string length
// defaulting to 13 for exceeding lengths
func getLen(str string) int {
	if len(str) < 13 {
		return 13
	}

	return len(str)
}

// prints a formatted key-value pair within a box layout,
// wrapping the value text if it exceeds the allowed width.
func printWrappedLine(keyColor, key, value string) {
	prefix := fmt.Sprintf("%s│%s %s%-13s%s : ", green, reset, keyColor, key, reset)
	prefixLen := len(prefix) - len(green) - len(reset) - len(keyColor) - len(reset)
	// the actual prefix size without colors
	actualPrefixLen := getLen(key) + 5

	lineWidth := boxWidth - prefixLen
	valueLines := wrapText(value, lineWidth)

	for i, line := range valueLines {
		if i == 0 {
			if len(line) < lineWidth {
				line += strings.Repeat(" ", lineWidth-len(line))
			}
			fmt.Printf("%s%s%s %s│%s\n", prefix, reset, line, green, reset)
		} else {
			line = strings.Repeat(" ", actualPrefixLen-2) + line
			if len(line) < boxWidth-4 {
				line += strings.Repeat(" ", boxWidth-len(line)-4)
			}
			fmt.Printf("%s│ %s%s %s│%s\n", green, reset, line, green, reset)
		}
	}
}

// wrapText splits the input text into lines of at most `width` characters each.
func wrapText(text string, width int) []string {
	var lines []string
	for len(text) > width {
		lines = append(lines, text[:width])
		text = text[width:]
	}
	if text != "" {
		lines = append(lines, text)
	}
	return lines
}

// TODO: remove this and use utils.IsBidDataAction after refactoring
// and creating 'internal' package
func isLargeDataAction(ctx *fiber.Ctx) bool {
	if ctx.Method() == http.MethodPut && len(strings.Split(ctx.Path(), "/")) >= 3 {
		if !ctx.Request().URI().QueryArgs().Has("tagging") && ctx.Get("X-Amz-Copy-Source") == "" && !ctx.Request().URI().QueryArgs().Has("acl") {
			return true
		}
	}
	return false
}
