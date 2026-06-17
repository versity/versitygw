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
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
)

type Color string
type prefix string

const (
	green  Color = "\033[32m"
	yellow Color = "\033[33m"
	blue   Color = "\033[34m"
	red    Color = "\033[31m"
	Purple Color = "\033[0;35m"

	prefixPanic        prefix = "[PANIC]: "
	prefixInernalError prefix = "[INTERNAL ERROR]: "
	prefixInfo         prefix = "[INFO]: "
	prefixDebug        prefix = "[DEBUG]: "

	reset             = "\033[0m"
	borderChar        = "─"
	boxWidth          = 120
	boxContentWidth   = boxWidth - 4 // visible width between "│ " and " │"
	minKeyColumnWidth = 13
	keyValueSeparator = " : "
)

// Panic prints the panics out in the console
func Panic(er error) {
	printError(prefixPanic, er)
}

// InternalError prints the internal error out in the console
func InternalError(er error) {
	printError(prefixInernalError, er)
}

func printError(prefix prefix, er error) {
	fmt.Fprintf(os.Stderr, string(red)+string(prefix)+"%v"+reset+"\n", er)
}

// Logs http request details: headers, body, params, query args
func LogFiberRequestDetails(ctx fiber.Ctx) {
	// Log the full request url
	fullURL := ctx.Scheme() + "://" + ctx.Host() + ctx.OriginalURL()
	fmt.Printf("%s[URL]: %s%s\n", green, fullURL, reset)

	// log request headers
	wrapInBox(green, "REQUEST HEADERS", boxWidth, func() {
		for key, value := range ctx.Request().Header.All() {
			printWrappedLine(yellow, string(key), string(value))
		}
	})
	// skip request body log for PutObject and UploadPart
	skipBodyLog := isLargeDataAction(ctx)
	if !skipBodyLog {
		body := ctx.Request().Body()
		if len(body) != 0 {
			printBoxTitleLine(blue, "REQUEST BODY", boxWidth, false)
			fmt.Printf("%s%s%s\n", blue, body, reset)
			printHorizontalBorder(blue, boxWidth, false)
		}
	}

	if ctx.Request().URI().QueryArgs().Len() != 0 {
		for key, value := range ctx.Request().URI().QueryArgs().All() {
			log.Printf("%s: %s", key, value)
		}
	}
}

// Logs http response details: body, headers
func LogFiberResponseDetails(ctx fiber.Ctx) {
	wrapInBox(green, "RESPONSE HEADERS", boxWidth, func() {
		for key, value := range ctx.Response().Header.All() {
			printWrappedLine(yellow, string(key), string(value))
		}
	})

	_, ok := ctx.Locals("skip-res-body-log").(bool)
	if !ok {
		body := ctx.Response().Body()
		if len(body) != 0 {
			PrintInsideHorizontalBorders(blue, "RESPONSE BODY", string(body), boxWidth)
		}
	}
}

var debugEnabled atomic.Bool

// SetDebugEnabled sets the debug mode
func SetDebugEnabled() {
	debugEnabled.Store(true)
}

// IsDebugEnabled returns true if debugging is enabled
func IsDebugEnabled() bool {
	return debugEnabled.Load()
}

// Logf is the same as 'fmt.Printf' with debug prefix,
// a color added and '\n' at the end
func Logf(format string, v ...any) {
	if !debugEnabled.Load() {
		return
	}

	fmt.Printf(string(yellow)+string(prefixDebug)+format+reset+"\n", v...)
}

// Infof prints out green info block with [INFO]: prefix
func Infof(format string, v ...any) {
	if !debugEnabled.Load() {
		return
	}

	fmt.Printf(string(green)+string(prefixInfo)+format+reset+"\n", v...)
}

var debugIAMEnabled atomic.Bool

// SetIAMDebugEnabled sets the IAM debug mode
func SetIAMDebugEnabled() {
	debugIAMEnabled.Store(true)
}

// IsDebugEnabled returns true if debugging enabled
func IsIAMDebugEnabled() bool {
	return debugEnabled.Load()
}

// IAMLogf is the same as 'fmt.Printf' with debug prefix,
// a color added and '\n' at the end
func IAMLogf(format string, v ...any) {
	if !debugIAMEnabled.Load() {
		return
	}

	fmt.Printf(string(yellow)+string(prefixDebug)+format+reset+"\n", v...)
}

// PrintInsideHorizontalBorders prints the text inside horizontal
// border and title in the center of upper border
func PrintInsideHorizontalBorders(color Color, title, text string, width int) {
	if !debugEnabled.Load() {
		return
	}
	printBoxTitleLine(color, title, width, false)
	fmt.Printf("%s%s%s\n", color, text, reset)
	printHorizontalBorder(color, width, false)
}

// Prints out box title either with closing characters or not:  "┌", "┐"
// e.g ┌────────────────[ RESPONSE HEADERS ]────────────────┐
func printBoxTitleLine(color Color, title string, length int, closing bool) {
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

	fmt.Println(string(color) + line + reset)
}

// Prints out a horizontal line either with closing characters or not: "└", "┘"
func printHorizontalBorder(color Color, length int, closing bool) {
	leftCorner, rightCorner := "└", "┘"
	if !closing {
		leftCorner, rightCorner = borderChar, borderChar
	}

	line := leftCorner + strings.Repeat(borderChar, length-2) + rightCorner + reset
	fmt.Println(string(color) + line)
}

// wrapInBox wraps the output of a function call (fn) inside a styled box with a title.
func wrapInBox(color Color, title string, length int, fn func()) {
	printBoxTitleLine(color, title, length, true)
	fn()
	printHorizontalBorder(color, length, true)
}

// paddedKeyLen returns the visible key column width used by printWrappedLine.
func paddedKeyLen(str string) int {
	if len(str) < minKeyColumnWidth {
		return minKeyColumnWidth
	}

	return len(str)
}

// prints a formatted key-value pair within a box layout,
// wrapping the value text if it exceeds the allowed width.
func printWrappedLine(keyColor Color, key, value string) {
	keyLen := paddedKeyLen(key)
	valueIndent := keyLen + len(keyValueSeparator)
	lineWidth := boxContentWidth - valueIndent
	if lineWidth < 1 {
		printWrappedLongKeyLine(keyColor, key, value)
		return
	}

	prefix := fmt.Sprintf("%s│%s %s%-*s%s%s", green, reset, keyColor, minKeyColumnWidth, key, reset, keyValueSeparator)
	valueLines := wrapText(value, lineWidth)
	if len(valueLines) == 0 {
		valueLines = []string{""}
	}

	for i, line := range valueLines {
		if i == 0 {
			line += rightPadding(line, lineWidth)
			fmt.Printf("%s%s%s %s│%s\n", prefix, reset, line, green, reset)
		} else {
			line = spaces(valueIndent) + line
			line += rightPadding(line, boxContentWidth)
			fmt.Printf("%s│ %s%s %s│%s\n", green, reset, line, green, reset)
		}
	}
}

// printWrappedLongKeyLine handles headers whose key is too wide to leave
// room for a value in the fixed key/value layout. It wraps the key and value
// independently so keyColor never leaks into the separator or value text.
func printWrappedLongKeyLine(keyColor Color, key, value string) {
	keyLine, remainingKey := splitText(key, boxContentWidth)
	for remainingKey != "" {
		printColoredBoxLine(keyColor, keyLine, boxContentWidth)
		keyLine, remainingKey = splitText(remainingKey, boxContentWidth)
	}

	valueLineWidth := boxContentWidth - len(keyLine) - len(keyValueSeparator)
	if valueLineWidth < 1 {
		printColoredBoxLine(keyColor, keyLine, boxContentWidth)
		printWrappedPlainText(keyValueSeparator+value, boxContentWidth)
		return
	}

	valueLine, remainingValue := splitText(value, valueLineWidth)
	printKeyValueBoxLine(keyColor, keyLine, keyValueSeparator, valueLine, boxContentWidth)
	printWrappedPlainText(remainingValue, boxContentWidth)
}

func printColoredBoxLine(color Color, text string, width int) {
	fmt.Printf("%s│%s %s%s%s%s %s│%s\n", green, reset, color, text, reset, rightPadding(text, width), green, reset)
}

func printKeyValueBoxLine(keyColor Color, key, separator, value string, width int) {
	lineLen := len(key) + len(separator) + len(value)
	fmt.Printf("%s│%s %s%s%s%s%s%s %s│%s\n", green, reset, keyColor, key, reset, separator, value, spaces(width-lineLen), green, reset)
}

func printPlainBoxLine(text string, width int) {
	fmt.Printf("%s│%s %s%s %s│%s\n", green, reset, text, rightPadding(text, width), green, reset)
}

func printWrappedPlainText(text string, width int) {
	for text != "" {
		var line string
		line, text = splitText(text, width)
		printPlainBoxLine(line, width)
	}
}

func rightPadding(text string, width int) string {
	return spaces(width - len(text))
}

func spaces(count int) string {
	if count < 1 {
		return ""
	}

	return strings.Repeat(" ", count)
}

// splitText returns the first width bytes from text and the remaining suffix.
// The debug logger already measures line width with len, so this keeps the
// wrapping behavior consistent with the rest of this file.
func splitText(text string, width int) (string, string) {
	if width < 1 {
		return "", text
	}
	if len(text) <= width {
		return text, ""
	}

	return text[:width], text[width:]
}

// wrapText splits the input text into lines of at most width bytes each.
// When width is not positive, it returns the original text as one line so
// callers never slice with an invalid bound while handling malformed layouts.
func wrapText(text string, width int) []string {
	if width < 1 {
		if text == "" {
			return nil
		}
		return []string{text}
	}

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
func isLargeDataAction(ctx fiber.Ctx) bool {
	pathParts := strings.Split(ctx.Path(), "/")

	// PutObject and UploadPart
	if ctx.Method() == http.MethodPut && len(pathParts) >= 3 {
		if !ctx.Request().URI().QueryArgs().Has("tagging") && ctx.Get("X-Amz-Copy-Source") == "" && !ctx.Request().URI().QueryArgs().Has("acl") {
			return true
		}
	}

	isBucketAction := (len(pathParts) == 3 && pathParts[2] == "") || (len(pathParts) == 2 && pathParts[1] != "")

	// POST object action
	if isBucketAction && ctx.Method() == http.MethodPost {
		return true
	}

	return false
}
