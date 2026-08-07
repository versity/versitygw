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
	"strings"
	"testing"
)

const stsBody = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><AssumedRoleUser><AssumedRoleId>AROAEXAMPLE:session</AssumedRoleId><Arn>arn:aws:sts::123456789012:assumed-role/role/session</Arn></AssumedRoleUser><Provider>https://idp.example.com</Provider><Credentials><AccessKeyId>ASIAabcdefghijklmnop</AccessKeyId><SecretAccessKey>supersecretvalue1234567890</SecretAccessKey><SessionToken>tokentokentokentoken</SessionToken><Expiration>2026-07-30T12:00:00Z</Expiration></Credentials><SubjectFromWebIdentityToken>subject-123</SubjectFromWebIdentityToken></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>req-123</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`

func TestMaskXMLBodyMasksSecretsAtDebugLevel(t *testing.T) {
	SetLevel(LevelDebug)
	defer SetLevel(LevelSilent)

	out, ok := maskXMLBody([]byte(stsBody))
	if !ok {
		t.Fatalf("maskXMLBody: expected ok=true for well-formed XML")
	}
	got := string(out)

	for _, secret := range []string{"supersecretvalue1234567890", "tokentokentokentoken"} {
		if strings.Contains(got, secret) {
			t.Errorf("masked output leaked secret %q:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "<SecretAccessKey>****</SecretAccessKey>") {
		t.Errorf("expected SecretAccessKey to be fully masked:\n%s", got)
	}
	if !strings.Contains(got, "<SessionToken>****</SessionToken>") {
		t.Errorf("expected SessionToken to be fully masked:\n%s", got)
	}
	// AccessKeyId is partially masked: first 4 chars visible.
	if !strings.Contains(got, "<AccessKeyId>ASIA****</AccessKeyId>") {
		t.Errorf("expected AccessKeyId to be partially masked with prefix visible:\n%s", got)
	}
	// Non-sensitive fields must survive untouched.
	for _, want := range []string{
		`xmlns="https://sts.amazonaws.com/doc/2011-06-15/"`,
		"<AssumedRoleId>AROAEXAMPLE:session</AssumedRoleId>",
		"<Arn>arn:aws:sts::123456789012:assumed-role/role/session</Arn>",
		"<Provider>https://idp.example.com</Provider>",
		"<Expiration>2026-07-30T12:00:00Z</Expiration>",
		"<RequestId>req-123</RequestId>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected masked output to preserve %q:\n%s", want, got)
		}
	}
	// The namespace must be declared exactly once (on the root), not
	// redeclared on every nested element.
	if n := strings.Count(got, "xmlns="); n != 1 {
		t.Errorf("expected exactly one xmlns declaration, got %d:\n%s", n, got)
	}
}

func TestMaskXMLBodyUnsafeLevelShowsSecrets(t *testing.T) {
	SetLevel(LevelUnsafe)
	defer SetLevel(LevelSilent)

	out, ok := maskXMLBody([]byte(stsBody))
	if !ok {
		t.Fatalf("maskXMLBody: expected ok=true for well-formed XML")
	}
	got := string(out)

	for _, secret := range []string{"supersecretvalue1234567890", "tokentokentokentoken", "ASIAabcdefghijklmnop"} {
		if !strings.Contains(got, secret) {
			t.Errorf("unsafe-level output should show secret %q in the clear:\n%s", secret, got)
		}
	}
}

func TestMaskXMLBodyPreservesNestingAndAttributes(t *testing.T) {
	SetLevel(LevelDebug)
	defer SetLevel(LevelSilent)

	body := `<Root xmlns="urn:example"><Outer id="1"><Inner>value</Inner><Inner>value2</Inner></Outer></Root>`
	out, ok := maskXMLBody([]byte(body))
	if !ok {
		t.Fatalf("maskXMLBody: expected ok=true")
	}
	got := string(out)

	if strings.Count(got, "<Inner>") != 2 {
		t.Errorf("expected both nested Inner elements to survive:\n%s", got)
	}
	if !strings.Contains(got, `id="1"`) {
		t.Errorf("expected attribute to survive:\n%s", got)
	}
}

func TestMaskXMLBodyRejectsMalformedOrNonXML(t *testing.T) {
	SetLevel(LevelDebug)
	defer SetLevel(LevelSilent)

	for _, body := range []string{
		"",
		"   ",
		"<Unclosed>",
		`{"json":"body"}`,
		"plain text body",
	} {
		if _, ok := maskXMLBody([]byte(body)); ok {
			t.Errorf("maskXMLBody(%q): expected ok=false", body)
		}
	}
}

func TestMaskPartial(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"AKIAabcdefghijklmnop", "AKIA****"},
		{"ASIA", "****"},
		{"abc", "****"},
		{"", "****"},
	}
	for _, tt := range tests {
		if got := maskPartial(tt.value); got != tt.want {
			t.Errorf("maskPartial(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
