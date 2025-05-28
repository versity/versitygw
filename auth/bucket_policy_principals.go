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
)

type Principals map[string]struct{}

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

// Validates Principals by checking user account access keys existence
func (p Principals) Validate(iam IAMService) error {
	_, containsWildCard := p["*"]
	if containsWildCard {
		if len(p) == 1 {
			return nil
		}
		return policyErrInvalidPrincipal
	}

	accs, err := CheckIfAccountsExist(p.ToSlice(), iam)
	if err != nil {
		return err
	}
	if len(accs) > 0 {
		return policyErrInvalidPrincipal
	}

	return nil
}

func (p Principals) Contains(userAccess string) bool {
	// "*" means it matches for any user account
	_, ok := p["*"]
	if ok {
		return true
	}

	_, found := p[userAccess]
	return found
}

// Bucket policy grants public access, if it contains
// a wildcard match to all the users
func (p Principals) IsPublic() bool {
	_, ok := p["*"]
	return ok
}
