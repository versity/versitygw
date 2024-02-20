package auth

import (
	"fmt"
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
}

var _ IAMService = &LdapIAMService{}

func NewLDAPService(url, bindDN, pass, queryBase, accAtr, secAtr, roleAtr, objClasses string) (IAMService, error) {
	if url == "" || bindDN == "" || pass == "" || queryBase == "" || accAtr == "" || secAtr == "" || roleAtr == "" || objClasses == "" {
		return nil, fmt.Errorf("required parameters list not fully provided")
	}
	conn, err := ldap.Dial("tcp", url)
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
	}, nil
}

func (ld *LdapIAMService) CreateAccount(account Account) error {
	userEntry := ldap.NewAddRequest(fmt.Sprintf("%v=%v, %v", ld.accessAtr, account.Access, ld.queryBase), nil)
	userEntry.Attribute("objectClass", ld.objClasses)
	userEntry.Attribute(ld.accessAtr, []string{account.Access})
	userEntry.Attribute(ld.secretAtr, []string{account.Secret})
	userEntry.Attribute(ld.roleAtr, []string{string(account.Role)})

	err := ld.conn.Add(userEntry)
	if err != nil {
		return fmt.Errorf("error adding an entry: %w", err)
	}

	return nil
}

func (ld *LdapIAMService) GetUserAccount(access string) (Account, error) {
	searchRequest := ldap.NewSearchRequest(
		ld.queryBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(%v=%v)", ld.accessAtr, access),
		[]string{ld.accessAtr, ld.secretAtr, ld.roleAtr},
		nil,
	)

	result, err := ld.conn.Search(searchRequest)
	if err != nil {
		return Account{}, err
	}

	entry := result.Entries[0]
	return Account{
		Access: entry.GetAttributeValue(ld.accessAtr),
		Secret: entry.GetAttributeValue(ld.secretAtr),
		Role:   Role(entry.GetAttributeValue(ld.roleAtr)),
	}, nil
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
		[]string{ld.accessAtr, ld.secretAtr, ld.roleAtr},
		nil,
	)

	resp, err := ld.conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	result := []Account{}
	for _, el := range resp.Entries {
		result = append(result, Account{
			Access: el.GetAttributeValue(ld.accessAtr),
			Secret: el.GetAttributeValue(ld.secretAtr),
			Role:   Role(el.GetAttributeValue(ld.roleAtr)),
		})
	}

	return result, nil
}

// Shutdown graceful termination of service
func (ld *LdapIAMService) Shutdown() error {
	return ld.conn.Close()
}
