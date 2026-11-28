package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLdapIAMService_BuildUserDN(t *testing.T) {
	ld := &LdapIAMService{
		accessAtr: "uid",
		queryBase: "dc=example,dc=com",
	}

	access := "admin,+;<>\\value"
	expected := `uid=admin\,\+\;\<\>\\value,dc=example,dc=com`

	if result := ld.buildUserDN(access); result != expected {
		t.Fatalf("buildUserDN() = %v, want %v", result, expected)
	}
}

func TestLdapIAMService_BuildSearchFilter(t *testing.T) {
	tests := []struct {
		name       string
		objClasses []string
		accessAtr  string
		access     string
		expected   string
	}{
		{
			name:       "single object class with access",
			objClasses: []string{"inetOrgPerson"},
			accessAtr:  "uid",
			access:     "testuser",
			expected:   "(&(objectClass=inetOrgPerson)(uid=testuser)(s3secret=*))",
		},
		{
			name:       "single object class without access",
			objClasses: []string{"inetOrgPerson"},
			accessAtr:  "uid",
			access:     "",
			expected:   "(&(objectClass=inetOrgPerson)(uid=*)(s3secret=*))",
		},
		{
			name:       "multiple object classes with access",
			objClasses: []string{"inetOrgPerson", "organizationalPerson"},
			accessAtr:  "cn",
			access:     "john.doe",
			expected:   "(&(objectClass=inetOrgPerson)(objectClass=organizationalPerson)(cn=john.doe)(s3secret=*))",
		},
		{
			name:       "multiple object classes without access",
			objClasses: []string{"inetOrgPerson", "organizationalPerson", "person"},
			accessAtr:  "cn",
			access:     "",
			expected:   "(&(objectClass=inetOrgPerson)(objectClass=organizationalPerson)(objectClass=person)(cn=*)(s3secret=*))",
		},
		{
			name:       "escape ldap filter metacharacters in access",
			objClasses: []string{"inetOrgPerson"},
			accessAtr:  "uid",
			access:     "admin)(s3secret=A*",
			expected:   "(&(objectClass=inetOrgPerson)(uid=admin\\29\\28s3secret=A\\2a)(s3secret=*))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &LdapIAMService{
				objClasses: tt.objClasses,
				accessAtr:  tt.accessAtr,
				secretAtr:  "s3secret",
			}

			result := ld.buildSearchFilter(tt.access)
			if result != tt.expected {
				t.Errorf("BuildSearchFilter() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLdapIAMService_EntryToAccount(t *testing.T) {
	ld := &LdapIAMService{
		accessAtr:    "vgw-access-key",
		secretAtr:    "vgw-secret-key",
		roleAtr:      "vgw-role",
		userIdAtr:    "vgw-uid",
		groupIdAtr:   "vgw-gid",
		projectIdAtr: "vgw-pid",
	}
	const dn = "uid=s3user,ou=people,dc=example,dc=com"

	tests := []struct {
		name     string
		attrs    map[string][]string
		expected Account
		err      error
		errPart  string
	}{
		{
			name: "every attribute",
			attrs: map[string][]string{
				"vgw-access-key": {"s3user"},
				"vgw-secret-key": {"secret"},
				"vgw-role":       {"userplus"},
				"vgw-uid":        {"1001"},
				"vgw-gid":        {"2001"},
				"vgw-pid":        {"3001"},
			},
			expected: Account{Access: "s3user", Secret: "secret", Role: RoleUserPlus,
				UserID: 1001, GroupID: 2001, ProjectID: 3001},
		},
		{
			name: "missing IDs read as 0",
			attrs: map[string][]string{
				"vgw-access-key": {"s3user"},
				"vgw-secret-key": {"secret"},
				"vgw-role":       {"user"},
			},
			expected: Account{Access: "s3user", Secret: "secret", Role: RoleUser},
		},
		// An entry without a secret key is not an account: a request signed
		// with an empty secret key would authenticate as it.
		{
			name: "missing secret key",
			attrs: map[string][]string{
				"vgw-access-key": {"s3user"},
				"vgw-role":       {"admin"},
				"vgw-uid":        {"1001"},
				"vgw-gid":        {"2001"},
				"vgw-pid":        {"3001"},
			},
			err: ErrNoSuchUser,
		},
		{
			name: "missing secret key and IDs",
			attrs: map[string][]string{
				"vgw-access-key": {"s3user"},
			},
			err: ErrNoSuchUser,
		},
		{
			name: "empty secret key",
			attrs: map[string][]string{
				"vgw-access-key": {"s3user"},
				"vgw-secret-key": {""},
			},
			err: ErrNoSuchUser,
		},
		{
			name: "missing access key",
			attrs: map[string][]string{
				"vgw-secret-key": {"secret"},
				"vgw-role":       {"user"},
			},
			err: ErrNoSuchUser,
		},
		{
			name: "invalid project ID",
			attrs: map[string][]string{
				"vgw-access-key": {"s3user"},
				"vgw-secret-key": {"secret"},
				"vgw-uid":        {"1001"},
				"vgw-gid":        {"2001"},
				"vgw-pid":        {"abc"},
			},
			errPart: `invalid project-id value "abc" (attribute vgw-pid) in entry "` + dn + `"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc, err := ld.entryToAccount(ldap.NewEntry(dn, tt.attrs))
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("entryToAccount() error = %v, want %v", err, tt.err)
				}
				return
			}
			if tt.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errPart) {
					t.Fatalf("entryToAccount() error = %v, want it to contain %q", err, tt.errPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("entryToAccount() unexpected error: %v", err)
			}
			if acc != tt.expected {
				t.Errorf("entryToAccount() = %+v, want %+v", acc, tt.expected)
			}
		})
	}
}

// An empty access key must not reach the directory: its search filter
// matches every account, which would make the first one look like a match.
func TestLdapIAMService_GetUserAccountEmptyAccess(t *testing.T) {
	ld := &LdapIAMService{rootAcc: Account{Access: "root"}}

	_, err := ld.GetUserAccount("")
	if !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("GetUserAccount(\"\") error = %v, want %v", err, ErrNoSuchUser)
	}
}
