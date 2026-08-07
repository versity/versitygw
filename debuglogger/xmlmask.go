// Copyright 2026 Versity Software
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
	"strings"
)

// accessKeyVisiblePrefixLen is the number of leading characters left
// visible when partially masking an access key ID (e.g. "AKIA" or "ASIA"),
// enough to identify the credential type without exposing the value.
const accessKeyVisiblePrefixLen = 4

// fullyMaskedXMLElements lists XML element (and attribute) local names
// whose text content is a usable credential. Every occurrence, at any
// nesting depth, is replaced with redactedValue when masking applies.
var fullyMaskedXMLElements = map[string]bool{
	"SecretAccessKey":  true,
	"SessionToken":     true,
	"WebIdentityToken": true,
}

// partiallyMaskedXMLElements lists XML element (and attribute) local names
// whose value is not itself a bearer credential but is still worth
// partially hiding. Only a short identifying prefix is left visible; see
// maskPartial.
var partiallyMaskedXMLElements = map[string]bool{
	"AccessKeyId": true,
}

// maskPartial reveals only the first accessKeyVisiblePrefixLen characters
// of value, replacing the rest with redactedValue. Values no longer than
// the visible prefix are masked in full, so short values are never fully
// exposed.
func maskPartial(value string) string {
	if len(value) <= accessKeyVisiblePrefixLen {
		return redactedValue
	}
	return value[:accessKeyVisiblePrefixLen] + redactedValue
}

// maskXMLValue returns the masked form of an XML element or attribute
// named name with text content value, per fullyMaskedXMLElements and
// partiallyMaskedXMLElements. It returns value unchanged when name isn't
// sensitive, or when unsafe is true (LevelUnsafe: print everything as-is).
func maskXMLValue(name, value string, unsafe bool) string {
	if unsafe {
		return value
	}
	if fullyMaskedXMLElements[name] {
		return redactedValue
	}
	if partiallyMaskedXMLElements[name] {
		return maskPartial(value)
	}
	return value
}

// xmlNode is an in-memory XML element tree, used so the pretty-printer can
// decide per element whether to inline its text content or nest its
// children, and can mask leaf text without disturbing surrounding
// structure, namespaces, or attributes.
type xmlNode struct {
	name     string
	space    string // namespace URI; only rendered at the root
	attrs    []xml.Attr
	text     string
	children []*xmlNode
}

// maskXMLBody parses body as XML, and returns a pretty-printed copy with
// sensitive element and attribute values masked (per maskXMLValue), and ok
// true. If body is not well-formed XML, it returns (nil, false) and the
// caller should fall back to printing the raw bytes.
//
// The parse-then-render round trip preserves the full document structure
// (namespace, nesting, attributes) exactly, since every element still
// carries its original name, namespace, attributes, and children; only leaf
// text content matching a sensitive field name is replaced.
func maskXMLBody(body []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return nil, false
	}

	dec := xml.NewDecoder(bytes.NewReader(body))
	root, xmlDecl, err := parseXMLTree(dec)
	if err != nil {
		return nil, false
	}

	var out bytes.Buffer
	if xmlDecl != "" {
		out.WriteString(xmlDecl)
		out.WriteByte('\n')
	}
	renderXMLNode(&out, root, 0, IsUnsafeEnabled())
	return out.Bytes(), true
}

// parseXMLTree reads tokens from dec up to and including the document's
// single root element, returning that element as a tree and the raw XML
// declaration (e.g. `<?xml version="1.0" encoding="UTF-8"?>`) if present.
func parseXMLTree(dec *xml.Decoder) (*xmlNode, string, error) {
	var xmlDecl string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, "", err
		}
		switch t := tok.(type) {
		case xml.ProcInst:
			if t.Target == "xml" {
				xmlDecl = fmt.Sprintf("<?xml %s?>", strings.TrimSpace(string(t.Inst)))
			}
		case xml.StartElement:
			root, err := parseXMLElement(dec, t)
			if err != nil {
				return nil, "", err
			}
			return root, xmlDecl, nil
		}
	}
}

// parseXMLElement reads dec until the matching end element for start,
// building the element subtree.
func parseXMLElement(dec *xml.Decoder, start xml.StartElement) (*xmlNode, error) {
	n := &xmlNode{name: start.Name.Local, space: start.Name.Space}
	for _, a := range start.Attr {
		// xmlns / xmlns:* declarations are re-derived from Name.Space when
		// rendering the root element; keep only "real" attributes here.
		if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
			continue
		}
		n.attrs = append(n.attrs, a)
	}

	var text bytes.Buffer
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child, err := parseXMLElement(dec, t)
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, child)
		case xml.EndElement:
			n.text = text.String()
			return n, nil
		case xml.CharData:
			text.Write(t)
		}
	}
}

// renderXMLNode writes n to out at the given indent depth, masking leaf
// text and attribute values per maskXMLValue.
func renderXMLNode(out *bytes.Buffer, n *xmlNode, depth int, unsafe bool) {
	out.WriteString(strings.Repeat("  ", depth))
	out.WriteByte('<')
	out.WriteString(n.name)
	if depth == 0 && n.space != "" {
		fmt.Fprintf(out, ` xmlns="%s"`, escapeXML(n.space))
	}
	for _, a := range n.attrs {
		attrName := a.Name.Local
		if a.Name.Space != "" {
			attrName = a.Name.Space + ":" + attrName
		}
		fmt.Fprintf(out, ` %s="%s"`, attrName, escapeXML(maskXMLValue(a.Name.Local, a.Value, unsafe)))
	}

	hasText := strings.TrimSpace(n.text) != ""
	if len(n.children) == 0 && !hasText {
		out.WriteString("></")
		out.WriteString(n.name)
		out.WriteString(">\n")
		return
	}

	out.WriteByte('>')
	if len(n.children) > 0 {
		out.WriteByte('\n')
		for _, c := range n.children {
			renderXMLNode(out, c, depth+1, unsafe)
		}
		out.WriteString(strings.Repeat("  ", depth))
	} else {
		out.WriteString(escapeXML(maskXMLValue(n.name, n.text, unsafe)))
	}
	out.WriteString("</")
	out.WriteString(n.name)
	out.WriteString(">\n")
}

func escapeXML(s string) string {
	var buf bytes.Buffer
	// xml.EscapeText never returns an error for a bytes.Buffer destination.
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
