package auth

import "testing"

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
			expected:   "(&(objectClass=inetOrgPerson)(uid=testuser))",
		},
		{
			name:       "single object class without access",
			objClasses: []string{"inetOrgPerson"},
			accessAtr:  "uid",
			access:     "",
			expected:   "(&(objectClass=inetOrgPerson))",
		},
		{
			name:       "multiple object classes with access",
			objClasses: []string{"inetOrgPerson", "organizationalPerson"},
			accessAtr:  "cn",
			access:     "john.doe",
			expected:   "(&(objectClass=inetOrgPerson)(objectClass=organizationalPerson)(cn=john.doe))",
		},
		{
			name:       "multiple object classes without access",
			objClasses: []string{"inetOrgPerson", "organizationalPerson", "person"},
			accessAtr:  "cn",
			access:     "",
			expected:   "(&(objectClass=inetOrgPerson)(objectClass=organizationalPerson)(objectClass=person))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &LdapIAMService{
				objClasses: tt.objClasses,
				accessAtr:  tt.accessAtr,
			}

			result := ld.buildSearchFilter(tt.access)
			if result != tt.expected {
				t.Errorf("BuildSearchFilter() = %v, want %v", result, tt.expected)
			}
		})
	}
}
