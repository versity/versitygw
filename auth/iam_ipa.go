package auth

import (
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
)

type IpaIAMService struct {
	client   http.Client
	host     string
	username string
	password string
	rootAcc  Account
}

var _ IAMService = &IpaIAMService{}

func (ipa *IpaIAMService) login() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	mTLSConfig := &tls.Config{InsecureSkipVerify: true}
	tr := &http.Transport{
		TLSClientConfig: mTLSConfig,
	}
	c := http.Client{Jar: jar, Transport: tr}

	ipa.client = c
	path := fmt.Sprintf("https://%s/ipa/session/login_password", ipa.host)
	form := url.Values{}
	form.Set("user", ipa.username)
	form.Set("password", ipa.password)

	req, err := http.NewRequest("POST", path, strings.NewReader(form.Encode()))

	if err != nil {
		return err
	}

	req.Header.Set("referer", fmt.Sprintf("https://%s/ipa", ipa.host))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = c.Do(req)

	if err != nil {
		return err
	}

	return nil
}

type IpaResult struct {
	Result struct {
		Json    interface{} `json:"result"`
		Value   string      `json:"value"`
		Summary any         `json:"summary"`
	} `json:"result"`
	Error     any    `json:"error"`
	ID        int    `json:"id"`
	Principal string `json:"principal"`
	Version   string `json:"version"`
}

type IpaUser struct {
	Dn        string
	Givenname []string
	Uid       []string
	Gidnumber []string
	Uidnumber []string
}

func (ipa *IpaIAMService) rpc(input string) (IpaResult, error) {
	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/ipa/session/json", ipa.host), strings.NewReader(input))
	if err != nil {
		return IpaResult{}, err
	}

	req.Header.Set("referer", "https://ipa.example.test/ipa")
	req.Header.Set("Content-Type", "application/json")

	resp, err := ipa.client.Do(req)
	if err != nil {
		return IpaResult{}, err
	}
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return IpaResult{}, err
	}

	data := IpaResult{}
	fmt.Println(json.Unmarshal(bytes, &data))

	return data, nil

}

func NewIpaIAMService(rootAcc Account, host, username, password string) (IAMService, error) {

	ipa := IpaIAMService{
		host:     host,
		username: username,
		password: password,
	}

	err := ipa.login()

	return &ipa, err
}

func (ipa *IpaIAMService) CreateAccount(account Account) error {
	return fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) GetUserAccount(access string) (Account, error) {
	if access == ipa.rootAcc.Access {
		return ipa.rootAcc, nil
	}

	user_request_template := `
	{
		"id": 0,
		"method": "user_show/1",
		"params": [
			[
				"%s"
			],
			{
				"version": "2.253"
			}
		]
	}
	`

	user_request := fmt.Sprintf(user_request_template, access)

	out, err := ipa.rpc(user_request)
	u := IpaUser{}
	mapstructure.Decode(out.Result.Json, &u)
	fmt.Println("printing user result")
	fmt.Println(out.Result.Json)
	fmt.Println(u)

	if err != nil {
		return Account{}, err
	}

	b := make([]byte, 256)
	rand.Read(b)
	base64Key := b64.StdEncoding.EncodeToString(b)

	secret_request_template := `
	{
		"id": 0,
		"method": "vault_retrieve_internal/1",
		"params": [
			[
				"versity"
			],
			{
				"version": "2.253",
				"username": "%s",
				"session_key": {
					"__base64__": "%s"
				},
				"wrapping_algo": "aes-128-cbc"
			}
		]
	}
	`

	secret_request := fmt.Sprintf(secret_request_template, access, base64Key)
	out, _ = ipa.rpc(secret_request)
	fmt.Println("printing vault data")
	fmt.Println(out)

	uidnumber, _ := strconv.ParseInt(u.Uidnumber[0], 10, 32)
	gidnumber, _ := strconv.ParseInt(u.Gidnumber[0], 10, 32)

	acc := Account{
		Access:  access,
		Secret:  "verysecret",
		Role:    RoleUser,
		UserID:  int(uidnumber),
		GroupID: int(gidnumber),
	}

	fmt.Println(acc)
	return acc, nil
}

func (ipa *IpaIAMService) UpdateUserAccount(access string, props MutableProps) error {
	return fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) DeleteUserAccount(access string) error {
	return fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) ListUserAccounts() ([]Account, error) {

	return []Account{}, fmt.Errorf("not implemented")

	/*	user_request := `
		{
			"id": 0,
			"method": "user_find/1",
			"params": [
				[
				],
				{
					"version": "2.253"
				}
			]
		}
		`
		out, err := ipa.rpc(user_request)
		if err != nil {
			return []Account{}, err
		}

		users := []IpaUser{}
		mapstructure.Decode(out.Result.Json, &users)

		accs := make([]Account, len(users))

		for i, u := range users {
			accs[i] = Account{
				Access:  u.uid,
				Secret:  "veryimportantsecret",
				Role:    RoleUser,
				UserID:  u.uidnumber,
				GroupID: u.gidnumber,
			}
		}

		return accs, nil
	*/
}

// Shutdown graceful termination of service
func (ipa *IpaIAMService) Shutdown() error {
	return nil
}
