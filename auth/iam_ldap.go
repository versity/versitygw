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
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-ldap/ldap/v3"
	"github.com/versity/versitygw/debuglogger"
)

type LdapIAMService struct {
	conn          *ldap.Conn
	queryBase     string
	objClasses    []string
	accessAtr     string
	secretAtr     string
	roleAtr       string
	groupIdAtr    string
	userIdAtr     string
	projectIdAtr  string
	rootAcc       Account
	url           string
	bindDN        string
	pass          string
	tlsSkipVerify bool
	mu            sync.Mutex
}

var _ IAMService = &LdapIAMService{}

func NewLDAPService(rootAcc Account, ldapURL, bindDN, pass, queryBase, accAtr, secAtr, roleAtr, userIdAtr, groupIdAtr, projectIdAtr, objClasses string, tlsSkipVerify bool) (IAMService, error) {
	if ldapURL == "" || bindDN == "" || pass == "" || queryBase == "" || accAtr == "" ||
		secAtr == "" || roleAtr == "" || userIdAtr == "" || groupIdAtr == "" || projectIdAtr == "" || objClasses == "" {
		return nil, fmt.Errorf("required parameters list not fully provided")
	}

	conn, err := dialLDAP(ldapURL, tlsSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	err = conn.Bind(bindDN, pass)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to bind to LDAP server %w", err)
	}
	return &LdapIAMService{
		conn:          conn,
		queryBase:     queryBase,
		objClasses:    strings.Split(objClasses, ","),
		accessAtr:     accAtr,
		secretAtr:     secAtr,
		roleAtr:       roleAtr,
		userIdAtr:     userIdAtr,
		groupIdAtr:    groupIdAtr,
		projectIdAtr:  projectIdAtr,
		rootAcc:       rootAcc,
		url:           ldapURL,
		bindDN:        bindDN,
		pass:          pass,
		tlsSkipVerify: tlsSkipVerify,
	}, nil
}

// dialLDAP establishes an LDAP connection with optional TLS configuration
func dialLDAP(ldapURL string, tlsSkipVerify bool) (*ldap.Conn, error) {
	u, err := url.Parse(ldapURL)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP URL: %w", err)
	}

	// For ldaps:// URLs, use DialURL with custom TLS config if needed
	if u.Scheme == "ldaps" && tlsSkipVerify {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: tlsSkipVerify,
		}
		return ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(tlsConfig))
	}

	// For ldap:// or when TLS verification is enabled, use standard DialURL
	return ldap.DialURL(ldapURL)
}

func (ld *LdapIAMService) reconnect() error {
	ld.conn.Close()

	conn, err := dialLDAP(ld.url, ld.tlsSkipVerify)
	if err != nil {
		return fmt.Errorf("failed to reconnect to LDAP server: %w", err)
	}

	err = conn.Bind(ld.bindDN, ld.pass)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to bind to LDAP server on reconnect: %w", err)
	}
	ld.conn = conn
	return nil
}

func (ld *LdapIAMService) execute(f func(*ldap.Conn) error) error {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	err := f(ld.conn)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok && e.ResultCode == ldap.ErrorNetwork {
			if reconnErr := ld.reconnect(); reconnErr != nil {
				return reconnErr
			}
			return f(ld.conn)
		}
	}
	return err
}

func (ld *LdapIAMService) CreateAccount(account Account) error {
	if ld.rootAcc.Access == account.Access {
		return ErrUserExists
	}
	userEntry := ldap.NewAddRequest(ld.buildUserDN(account.Access), nil)
	userEntry.Attribute("objectClass", ld.objClasses)
	userEntry.Attribute(ld.accessAtr, []string{account.Access})
	userEntry.Attribute(ld.secretAtr, []string{account.Secret})
	userEntry.Attribute(ld.roleAtr, []string{string(account.Role)})
	userEntry.Attribute(ld.groupIdAtr, []string{fmt.Sprint(account.GroupID)})
	userEntry.Attribute(ld.userIdAtr, []string{fmt.Sprint(account.UserID)})
	userEntry.Attribute(ld.projectIdAtr, []string{fmt.Sprint(account.ProjectID)})

	err := ld.execute(func(c *ldap.Conn) error {
		return c.Add(userEntry)
	})
	if err != nil {
		return fmt.Errorf("error adding an entry: %w", err)
	}

	return nil
}

func (ld *LdapIAMService) buildUserDN(access string) string {
	return fmt.Sprintf("%v=%v,%v", ld.accessAtr, ldap.EscapeDN(access), ld.queryBase)
}

// buildSearchFilter matches the account with the given access key, or every
// account when access is empty. The query base can also hold directory users
// of the configured object classes that are not S3 accounts, and they all
// carry the access key attribute when it is a common one such as uid, so
// only entries that carry both an access key and a secret key are accounts.
func (ld *LdapIAMService) buildSearchFilter(access string) string {
	var searchFilter strings.Builder
	for _, el := range ld.objClasses {
		searchFilter.WriteString(fmt.Sprintf("(objectClass=%v)", el))
	}
	value := "*"
	if access != "" {
		value = ldap.EscapeFilter(access)
	}
	searchFilter.WriteString(fmt.Sprintf("(%v=%v)", ld.accessAtr, value))
	searchFilter.WriteString(fmt.Sprintf("(%v=*)", ld.secretAtr))
	return fmt.Sprintf("(&%v)", searchFilter.String())
}

// entryToAccount converts an account entry of the directory. An entry
// without an access key or a secret key is not an account and converts to
// ErrNoSuchUser: a request signed with an empty secret key would otherwise
// authenticate as it. A user, group or project ID attribute the entry lacks
// reads as 0, the ID CreateAccount stores for an account created without
// one; only an entry provisioned directly in the directory can lack it.
func (ld *LdapIAMService) entryToAccount(entry *ldap.Entry) (Account, error) {
	access := entry.GetAttributeValue(ld.accessAtr)
	secret := entry.GetAttributeValue(ld.secretAtr)
	if access == "" || secret == "" {
		return Account{}, ErrNoSuchUser
	}

	parseID := func(name, atr string) (int, error) {
		val := entry.GetAttributeValue(atr)
		if val == "" {
			return 0, nil
		}
		id, err := strconv.Atoi(val)
		if err != nil {
			return 0, fmt.Errorf("invalid %v value %q (attribute %v) in entry %q: %w",
				name, val, atr, entry.DN, err)
		}
		return id, nil
	}

	userID, err := parseID("user-id", ld.userIdAtr)
	if err != nil {
		return Account{}, err
	}
	groupID, err := parseID("group-id", ld.groupIdAtr)
	if err != nil {
		return Account{}, err
	}
	projectID, err := parseID("project-id", ld.projectIdAtr)
	if err != nil {
		return Account{}, err
	}

	return Account{
		Access:    access,
		Secret:    secret,
		Role:      Role(entry.GetAttributeValue(ld.roleAtr)),
		UserID:    userID,
		GroupID:   groupID,
		ProjectID: projectID,
	}, nil
}

func (ld *LdapIAMService) GetUserAccount(access string) (Account, error) {
	if access == ld.rootAcc.Access {
		return ld.rootAcc, nil
	}
	// No account has an empty access key, and the search filter for an
	// empty one matches every account.
	if access == "" {
		return Account{}, ErrNoSuchUser
	}
	var result *ldap.SearchResult
	searchRequest := ldap.NewSearchRequest(
		ld.queryBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		ld.buildSearchFilter(access),
		[]string{ld.accessAtr, ld.secretAtr, ld.roleAtr, ld.userIdAtr, ld.groupIdAtr, ld.projectIdAtr},
		nil,
	)

	if debuglogger.IsIAMDebugEnabled() {
		debuglogger.IAMLogf("LDAP Search Request")
		debuglogger.IAMLogf(spew.Sdump(searchRequest))
	}

	err := ld.execute(func(c *ldap.Conn) error {
		var err error
		result, err = c.Search(searchRequest)
		return err
	})

	if debuglogger.IsIAMDebugEnabled() {
		debuglogger.IAMLogf("LDAP Search Result")
		debuglogger.IAMLogf(spew.Sdump(result))
	}

	if err != nil {
		return Account{}, err
	}

	if len(result.Entries) == 0 {
		return Account{}, ErrNoSuchUser
	}

	return ld.entryToAccount(result.Entries[0])
}

// ResolveAccounts returns the subset of accessKeyIDs that do not exist.
func (ld *LdapIAMService) ResolveAccounts(accessKeyIDs []string) ([]string, error) {
	return resolveAccountsByLookup(accessKeyIDs, ld.GetUserAccount)
}

func (ld *LdapIAMService) UpdateUserAccount(access string, props MutableProps) error {
	req := ldap.NewModifyRequest(ld.buildUserDN(access), nil)
	if props.Secret != nil {
		req.Replace(ld.secretAtr, []string{*props.Secret})
	}
	if props.GroupID != nil {
		req.Replace(ld.groupIdAtr, []string{fmt.Sprint(*props.GroupID)})
	}
	if props.UserID != nil {
		req.Replace(ld.userIdAtr, []string{fmt.Sprint(*props.UserID)})
	}
	if props.ProjectID != nil {
		req.Replace(ld.projectIdAtr, []string{fmt.Sprint(*props.ProjectID)})
	}
	if props.Role != "" {
		req.Replace(ld.roleAtr, []string{string(props.Role)})
	}

	err := ld.execute(func(c *ldap.Conn) error {
		return c.Modify(req)
	})
	//TODO: Handle non existing user case
	if err != nil {
		return err
	}
	return nil
}

func (ld *LdapIAMService) DeleteUserAccount(access string) error {
	delReq := ldap.NewDelRequest(ld.buildUserDN(access), nil)

	err := ld.execute(func(c *ldap.Conn) error {
		return c.Del(delReq)
	})
	if err != nil {
		return err
	}

	return nil
}

func (ld *LdapIAMService) ListUserAccounts() ([]Account, error) {
	var resp *ldap.SearchResult
	searchRequest := ldap.NewSearchRequest(
		ld.queryBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		ld.buildSearchFilter(""),
		[]string{ld.accessAtr, ld.secretAtr, ld.roleAtr, ld.groupIdAtr, ld.projectIdAtr, ld.userIdAtr},
		nil,
	)

	err := ld.execute(func(c *ldap.Conn) error {
		var err error
		resp, err = c.Search(searchRequest)
		return err
	})
	if err != nil {
		return nil, err
	}

	result := []Account{}
	for _, el := range resp.Entries {
		acc, err := ld.entryToAccount(el)
		if errors.Is(err, ErrNoSuchUser) {
			// not an account
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, acc)
	}

	return result, nil
}

// Shutdown graceful termination of service
func (ld *LdapIAMService) Shutdown() error {
	ld.mu.Lock()
	defer ld.mu.Unlock()
	return ld.conn.Close()
}
