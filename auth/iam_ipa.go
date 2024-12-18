package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
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

type IpaVaultData struct {
	Nonce struct {
		Base64 string `mapstructure:"__base64__"`
	} `mapstructure:"nonce"`
	Vault_data struct {
		Base64 string `mapstructure:"__base64__"`
	} `mapstructure:"vault_data"`
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
	json.Unmarshal(bytes, &data)
	fmt.Println(data)

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

// PKCS7 errors.
var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
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

	b := make([]byte, 16)
	rand.Read(b)

	ipa_cert := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8l+tmcQ+hvZXTqWz5DX
2n6m+CJImAocIbPeqJdYrFrNj6IE+T8xswLU7CwLSdagfitO56l1/fTqJ4cmo2NR
Yws/PgnOD9EbH/uepfKYXM9E4ictLtyHvfTwuP0L7rwAn5IsSNS0+oTkWk4zO2Ft
sVUzXUEJG+6Cn/ShdLRi/8BSRoHZQ/rQTjxYWZnKJi+qjLv2JoEqIRjtu1XkwBXq
Tp28UzFmTNs3IWDGtE+0ewjc7Sey288NUWNYTsuvJre6LoCl6LeIClS52+XfmNH/
m+I7wTGMqtbBhYr4uaOKBj65/7mhmsqo8o1FW97xnVYji7qJu70JMNubzgnmqjYh
pQIDAQAB
-----END PUBLIC KEY-----
	`
	block, _ := pem.Decode([]byte(ipa_cert))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	pubKey, _ := key.(*rsa.PublicKey)
	println(pubKey)
	result, _ := rsa.EncryptPKCS1v15(rand.Reader, pubKey, b)
	println("encoded result " + b64.StdEncoding.EncodeToString(result))

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

	secret_request := fmt.Sprintf(secret_request_template, access, b64.StdEncoding.EncodeToString(result))
	out, _ = ipa.rpc(secret_request)
	fmt.Println("printing vault data")

	d := IpaVaultData{}
	mapstructure.Decode(out.Result.Json, &d)
	fmt.Println(out.Result.Json)
	fmt.Println(d)
	aes, err := aes.NewCipher(b)

	fmt.Println(err)
	//cbc := aes.CBC{Aes: *eas1, Padding: &PCKS7Padding{}}
	nonce, _ := b64.StdEncoding.DecodeString(d.Nonce.Base64)
	cbc := cipher.NewCBCDecrypter(aes, nonce)
	println(d.Nonce.Base64)
	println(len(nonce))
	ctext, _ := b64.StdEncoding.DecodeString(d.Vault_data.Base64)
	var ptext []byte = make([]byte, len(ctext))
	cbc.CryptBlocks(ptext, ctext)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ptext)

	type VaultData struct {
		Data string `json:"data"`
	}

	vd := VaultData{}

	ptext_unpadded, err := pkcs7Unpad(ptext, 16)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(json.Unmarshal(ptext_unpadded, &vd))
	fmt.Println("data part is " + vd.Data)

	secret, _ := b64.StdEncoding.DecodeString(vd.Data)

	uidnumber, _ := strconv.ParseInt(u.Uidnumber[0], 10, 32)
	gidnumber, _ := strconv.ParseInt(u.Gidnumber[0], 10, 32)

	acc := Account{
		Access:  access,
		Secret:  string(secret),
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
