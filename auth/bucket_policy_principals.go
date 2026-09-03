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

package auth

import (
	"encoding/json"
	"strings"
)

type Principals map[string]struct{}

// principalMatch is how strongly a Principal element matched a caller. The
// three cases are not interchangeable: a statement naming the account
// (principalAccountMatch) delegates rather than grants, so it means different things
// under Allow and under Deny
type principalMatch int

const (
	// principalNoMatch means the statement does not cover this caller.
	principalNoMatch principalMatch = iota
	// principalAccountMatch means the statement names the caller's account
	// — its root ARN, or the bare account id — and so covers the caller
	// only in the delegating sense.
	principalAccountMatch
	// principalDirectMatch means the statement names the caller itself, the
	// role it assumed, or every principal ("*").
	principalDirectMatch
)

func (p Principals) Add(key string) {
	p[key] = struct{}{}
}

// Override UnmarshalJSON method to decode both []string and string properties
func (p *Principals) UnmarshalJSON(data []byte) error {
	ss := []string{}
	var s string
	var k struct {
		AWS string
	}

	var err error

	if err = json.Unmarshal(data, &ss); err == nil {
		if len(ss) == 0 {
			return policyErrInvalidPrincipal
		}
		*p = make(Principals)
		for _, s := range ss {
			p.Add(s)
		}
		return nil
	} else if err = json.Unmarshal(data, &s); err == nil {
		if s == "" {
			return policyErrInvalidPrincipal
		}
		*p = make(Principals)
		p.Add(s)

		return nil
	} else if err = json.Unmarshal(data, &k); err == nil {
		if k.AWS == "" {
			return policyErrInvalidPrincipal
		}
		*p = make(Principals)
		p.Add(k.AWS)

		return nil
	} else {
		var sk struct {
			AWS []string
		}
		if err = json.Unmarshal(data, &sk); err == nil {
			if len(sk.AWS) == 0 {
				return policyErrInvalidPrincipal
			}
			*p = make(Principals)
			for _, s := range sk.AWS {
				p.Add(s)
			}
		}
	}

	return err
}

// Converts Principals map to a slice, by omitting "*"
func (p Principals) ToSlice() []string {
	principals := []string{}
	for p := range p {
		if p == "*" {
			continue
		}
		principals = append(principals, p)
	}

	return principals
}

// Validate checks that every principal named here exists, so a policy can
// never be stored naming somebody who cannot be matched. What a principal
// *is* depends on the IAM backend: an AWS-style ARN for a backend that
// implements PrincipalResolver, and an access key id for every other one.
//
// The wildcard is checked the same way either way: "*" is only valid alone,
// never mixed with named principals.
func (p Principals) Validate(iam IAMService) error {
	_, containsWildCard := p["*"]
	if containsWildCard {
		if len(p) == 1 {
			return nil
		}
		return policyErrInvalidPrincipal
	}

	if pr, ok := iam.(PrincipalResolver); ok {
		invalid, err := pr.ResolvePrincipals(p.ToSlice())
		if err != nil {
			return principalLookupError{err}
		}
		if len(invalid) > 0 {
			return policyErrInvalidPrincipal
		}
		return nil
	}

	accs, err := iam.ResolveAccounts(p.ToSlice())
	if err != nil {
		return err
	}
	if len(accs) > 0 {
		return policyErrInvalidPrincipal
	}

	return nil
}

// principalLookupError reports that the IAM service could not be asked
// whether a policy's principals exist, as distinct from its answering that
// one of them does not. Validating an ARN principal is a network call, so
// this is the difference between telling an operator their IAM service is
// unreachable and telling a user their policy is malformed
type principalLookupError struct{ err error }

func (e principalLookupError) Error() string { return e.err.Error() }
func (e principalLookupError) Unwrap() error { return e.err }

// matchFor reports how this Principal element covers acc.
//
// An account whose IAM backend gives it an ARN (acc.Arn set, i.e. the
// standalone IAM service) is matched by ARN, the way real S3 does it:
//
//   - "*" matches everyone, authenticated or not.
//   - The caller's own ARN matches it and nothing else. For an assumed-role
//     session that is arn:aws:sts::…:assumed-role/<role>/<session>, so a
//     statement naming one session does not cover another session of the
//     same role.
//   - A session's role ARN matches every session of that role, which is the
//     only way to name them all: no wildcard is allowed inside an ARN.
//   - The account's root ARN, and the bare account id, match as a
//     delegation rather than as a grant. The gateway's own root account is
//     the exception, and not a special case: the account root ARN is its
//     own ARN, so it matches root directly and the account only by
//     delegation, which is what the same string means for each of them.
//
// Everything else is left to the IAM backend to have rejected at
// PutBucketPolicy time; matching is a plain string comparison, and
// deliberately so — no case folding, no whitespace trimming, no wildcards
// within an ARN.
//
// An account with no ARN — every other IAM backend — is matched by access
// key id exactly as it always has been.
func (p Principals) matchFor(acc Account) principalMatch {
	if _, ok := p["*"]; ok {
		return principalDirectMatch
	}

	if acc.Arn == "" {
		if _, found := p[acc.Access]; found {
			return principalDirectMatch
		}
		return principalNoMatch
	}

	if _, found := p[acc.Arn]; found {
		return principalDirectMatch
	}
	if acc.RoleArn != "" {
		if _, found := p[acc.RoleArn]; found {
			return principalDirectMatch
		}
	}

	accountID := accountIDFromArn(acc.Arn)
	if accountID == "" {
		return principalNoMatch
	}
	if _, found := p[accountID]; found {
		return principalAccountMatch
	}
	if _, found := p[accountRootArn(accountID)]; found {
		return principalAccountMatch
	}

	return principalNoMatch
}

// Bucket policy grants public access, if it contains
// a wildcard match to all the users
func (p Principals) isPublic() bool {
	_, ok := p["*"]
	return ok
}

// accountIDFromArn returns the account id field of arn, or "" if arn isn't
// shaped like one. It reads the caller's own ARN, which the IAM service
// built, so it needs to recognize no more than the two shapes that service
// produces: arn:<partition>:<service>::<account>:<resource>.
func accountIDFromArn(arn string) string {
	const fields = 6
	parts := strings.SplitN(arn, ":", fields)
	if len(parts) != fields || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

// accountRootArn builds the ARN naming an account itself, the principal
// form that delegates to it.
func accountRootArn(accountID string) string {
	return "arn:aws:iam::" + accountID + ":root"
}
