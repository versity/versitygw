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
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LdapIAMService struct {
	conn       *ldap.Conn
	queryBase  string
	objClasses []string
	accessAtr  string
	secretAtr  string
	roleAtr    string
	groupIdAtr string
	userIdAtr  string
	rootAcc    Account
}

var _ IAMService = &LdapIAMService{}

func NewLDAPService(rootAcc Account, url, bindDN, pass, queryBase, accAtr, secAtr, roleAtr, userIdAtr, groupIdAtr, objClasses string) (IAMService, error) {
	if url == "" || bindDN == "" || pass == "" || queryBase == "" || accAtr == "" ||
		secAtr == "" || roleAtr == "" || userIdAtr == "" || groupIdAtr == "" || objClasses == "" {
		return nil, fmt.Errorf("required parameters list not fully provided")
	}
	conn, err := ldap.DialURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	err = conn.Bind(bindDN, pass)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP server %w", err)
	}
	return &LdapIAMService{
		conn:       conn,
		queryBase:  queryBase,
		objClasses: strings.Split(objClasses, ","),
		accessAtr:  accAtr,
		secretAtr:  secAtr,
		roleAtr:    roleAtr,
		userIdAtr:  userIdAtr,
		groupIdAtr: groupIdAtr,
		rootAcc:    rootAcc,
	}, nil
}

func (ld *LdapIAMService) CreateAccount(account Account) error {
	if ld.rootAcc.Access == account.Access {
		return ErrUserExists
	}
	userEntry := ldap.NewAddRequest(fmt.Sprintf("%v=%v,%v", ld.accessAtr, account.Access, ld.queryBase), nil)
	userEntry.Attribute("objectClass", ld.objClasses)
	userEntry.Attribute(ld.accessAtr, []string{account.Access})
	userEntry.Attribute(ld.secretAtr, []string{account.Secret})
	userEntry.Attribute(ld.roleAtr, []string{string(account.Role)})
	userEntry.Attribute(ld.groupIdAtr, []string{fmt.Sprint(account.GroupID)})
	userEntry.Attribute(ld.userIdAtr, []string{fmt.Sprint(account.UserID)})

	err := ld.conn.Add(userEntry)
	if err != nil {
		return fmt.Errorf("error adding an entry: %w", err)
	}

	return nil
}

func (ld *LdapIAMService) GetUserAccount(access string) (Account, error) {
	if access == ld.rootAcc.Access {
		return ld.rootAcc, nil
	}
	searchRequest := ldap.NewSearchRequest(
		ld.queryBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(%v=%v)", ld.accessAtr, access),
		[]string{ld.accessAtr, ld.secretAtr, ld.roleAtr, ld.userIdAtr, ld.groupIdAtr},
		nil,
	)

	result, err := ld.conn.Search(searchRequest)
	if err != nil {
		return Account{}, err
	}

	if len(result.Entries) == 0 {
		return Account{}, ErrNoSuchUser
	}

	entry := result.Entries[0]
	groupId, err := strconv.Atoi(entry.GetAttributeValue(ld.groupIdAtr))
	if err != nil {
		return Account{}, fmt.Errorf("invalid entry value for group-id %q: %w",
			entry.GetAttributeValue(ld.groupIdAtr), err)
	}
	userId, err := strconv.Atoi(entry.GetAttributeValue(ld.userIdAtr))
	if err != nil {
		return Account{}, fmt.Errorf("invalid entry value for user-id %q: %w",
			entry.GetAttributeValue(ld.userIdAtr), err)
	}
	return Account{
		Access:  entry.GetAttributeValue(ld.accessAtr),
		Secret:  entry.GetAttributeValue(ld.secretAtr),
		Role:    Role(entry.GetAttributeValue(ld.roleAtr)),
		GroupID: groupId,
		UserID:  userId,
	}, nil
}

func (ld *LdapIAMService) UpdateUserAccount(access string, props MutableProps) error {
	req := ldap.NewModifyRequest(fmt.Sprintf("%v=%v, %v", ld.accessAtr, access, ld.queryBase), nil)
	if props.Secret != nil {
		req.Replace(ld.secretAtr, []string{*props.Secret})
	}
	if props.GroupID != nil {
		req.Replace(ld.groupIdAtr, []string{fmt.Sprint(*props.GroupID)})
	}
	if props.UserID != nil {
		req.Replace(ld.userIdAtr, []string{fmt.Sprint(*props.UserID)})
	}
	if props.Role != "" {
		req.Replace(ld.roleAtr, []string{string(props.Role)})
	}

	err := ld.conn.Modify(req)
	//TODO: Handle non existing user case
	if err != nil {
		return err
	}
	return nil
}

func (ld *LdapIAMService) DeleteUserAccount(access string) error {
	delReq := ldap.NewDelRequest(fmt.Sprintf("%v=%v, %v", ld.accessAtr, access, ld.queryBase), nil)

	err := ld.conn.Del(delReq)
	if err != nil {
		return err
	}

	return nil
}

func (ld *LdapIAMService) ListUserAccounts() ([]Account, error) {
	searchFilter := ""
	for _, el := range ld.objClasses {
		searchFilter += fmt.Sprintf("(objectClass=%v)", el)
	}
	searchRequest := ldap.NewSearchRequest(
		ld.queryBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&%v)", searchFilter),
		[]string{ld.accessAtr, ld.secretAtr, ld.roleAtr, ld.groupIdAtr, ld.userIdAtr},
		nil,
	)

	resp, err := ld.conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	result := []Account{}
	for _, el := range resp.Entries {
		groupId, err := strconv.Atoi(el.GetAttributeValue(ld.groupIdAtr))
		if err != nil {
			return nil, fmt.Errorf("invalid entry value for group-id %q: %w",
				el.GetAttributeValue(ld.groupIdAtr), err)
		}
		userId, err := strconv.Atoi(el.GetAttributeValue(ld.userIdAtr))
		if err != nil {
			return nil, fmt.Errorf("invalid entry value for user-id %q: %w",
				el.GetAttributeValue(ld.userIdAtr), err)
		}
		result = append(result, Account{
			Access:  el.GetAttributeValue(ld.accessAtr),
			Secret:  el.GetAttributeValue(ld.secretAtr),
			Role:    Role(el.GetAttributeValue(ld.roleAtr)),
			GroupID: groupId,
			UserID:  userId,
		})
	}

	return result, nil
}

// Shutdown graceful termination of service
func (ld *LdapIAMService) Shutdown() error {
	return ld.conn.Close()
}
