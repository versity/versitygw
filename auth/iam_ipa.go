package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
)

const IpaVersion = "2.254"

type ipaIAMService struct {
	client          http.Client
	id              int
	version         string
	host            string
	vaultName       string
	username        string
	password        string
	kraTransportKey *rsa.PublicKey
	debug           bool
	rootAcc         Account
}

//var _ IAMService = &ipaIAMService{}

func NewIpaIAMService(rootAcc Account, host, vaultName, username, password string, isInsecure, debug bool) (IAMService, error) {

	ipa := ipaIAMService{
		id:        0,
		version:   IpaVersion,
		host:      host,
		vaultName: vaultName,
		username:  username,
		password:  password,
		debug:     debug,
		rootAcc:   rootAcc,
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		// this should never happen
		panic(err)
	}

	mTLSConfig := &tls.Config{InsecureSkipVerify: isInsecure}
	tr := &http.Transport{
		TLSClientConfig: mTLSConfig,
	}
	ipa.client = http.Client{Jar: jar, Transport: tr}

	err = ipa.login()
	if err != nil {
		return nil, err
	}

	req := ipa.newRequest("vaultconfig_show/1", []string{}, map[string]any{"all": true})
	vaultConfig := struct {
		Kra_Server_Server             []string
		Transport_Cert                Base64EncodedWrapped
		Wrapping_default_algorithm    string
		Wrapping_supported_algorithms []string
	}{}
	_, err = ipa.rpc(req, &vaultConfig)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(vaultConfig.Transport_Cert)
	if err != nil {
		return nil, err
	}

	ipa.kraTransportKey = cert.PublicKey.(*rsa.PublicKey)

	isSupported := false
	for _, algo := range vaultConfig.Wrapping_supported_algorithms {
		if algo == "aes-128-cbc" {
			isSupported = true
			break
		}
	}

	if !isSupported {
		return nil, fmt.Errorf("IPA vault does not support aes-128-cbc. Only %v supported", vaultConfig.Wrapping_supported_algorithms)
	}
	return &ipa, nil
}

func (ipa *ipaIAMService) CreateAccount(account Account) error {
	return fmt.Errorf("not implemented")
}

func (ipa *ipaIAMService) GetUserAccount(access string) (Account, error) {
	if access == ipa.rootAcc.Access {
		return ipa.rootAcc, nil
	}

	req := ipa.newRequest("user_show/1", []string{access}, map[string]any{})

	userResult := struct {
		Gidnumber []string
		Uidnumber []string
	}{}
	_, err := ipa.rpc(req, &userResult)
	if err != nil {
		return Account{}, err
	}

	uid, _ := strconv.Atoi(userResult.Uidnumber[0])
	gid, _ := strconv.Atoi(userResult.Gidnumber[0])
	account := Account{
		Access:  access,
		Role:    RoleUser,
		UserID:  uid,
		GroupID: gid,
	}

	session_key := make([]byte, 16)
	rand.Read(session_key)
	encrypted_key, err := rsa.EncryptPKCS1v15(rand.Reader, ipa.kraTransportKey, session_key)
	if err != nil {
		return account, err
	}
	req = ipa.newRequest("vault_retrieve_internal/1", []string{ipa.vaultName},
		map[string]any{"username": access,
			"session_key":   Base64EncodedWrapped(encrypted_key),
			"wrapping_algo": "aes-128-cbc"})
	data := struct {
		Vault_data Base64EncodedWrapped
		Nonce      Base64EncodedWrapped
	}{}
	_, err = ipa.rpc(req, &data)
	if err != nil {
		return account, err
	}

	aes, _ := aes.NewCipher(session_key)
	cbc := cipher.NewCBCDecrypter(aes, data.Nonce)
	cbc.CryptBlocks(data.Vault_data, data.Vault_data)
	secret_unpadded_json, _ := pkcs7Unpad(data.Vault_data, 16)

	secret := struct {
		Data Base64Encoded
	}{}
	json.Unmarshal(secret_unpadded_json, &secret)
	account.Secret = string(secret.Data)

	fmt.Printf("%v\n", account)
	return account, nil
}

func (ipa *ipaIAMService) UpdateUserAccount(access string, props MutableProps) error {
	return fmt.Errorf("not implemented")
}

func (ipa *ipaIAMService) DeleteUserAccount(access string) error {
	return fmt.Errorf("not implemented")
}

func (ipa *ipaIAMService) ListUserAccounts() ([]Account, error) {
	return []Account{}, fmt.Errorf("not implemented")
}

func (ipa *ipaIAMService) Shutdown() error {
	return nil
}

// Implementation

func (ipa *ipaIAMService) login() error {
	form := url.Values{}
	form.Set("user", ipa.username)
	form.Set("password", ipa.password)

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/ipa/session/login_password", ipa.host),
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("referer", fmt.Sprintf("%s/ipa", ipa.host))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ipa.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == 401 {
		return errors.New("cannot login to FreeIPA: invalid credentials")
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("cannot login to FreeIPA: status code %d", resp.StatusCode)
	}
	return nil
}

type rpcRequest = string

type rpcResponse struct {
	Result    json.RawMessage
	Principal string
	Id        int
	Version   string
}

func (p rpcResponse) String() string {
	return string(p.Result)
}

var errRpc = errors.New("IPA RPC error")

func (ipa *ipaIAMService) rpc(req rpcRequest, value any) (rpcResponse, error) {

	err := ipa.login()
	if err != nil {
		return rpcResponse{}, err
	}

	res, err := ipa.rpcInternal(req)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(res.Result, value)
	return res, err
}

func (ipa *ipaIAMService) rpcInternal(req rpcRequest) (rpcResponse, error) {

	httpReq, err := http.NewRequest("POST",
		fmt.Sprintf("%s/ipa/session/json", ipa.host),
		strings.NewReader(req))
	if err != nil {
		return rpcResponse{}, err
	}

	ipa.log(fmt.Sprintf("%v\n", req))
	httpReq.Header.Set("referer", fmt.Sprintf("%s/ipa", ipa.host))
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := ipa.client.Do(httpReq)
	if err != nil {
		return rpcResponse{}, err
	}

	bytes, err := io.ReadAll(httpResp.Body)
	ipa.log(fmt.Sprintf("%v\n", string(bytes)))
	if err != nil {
		return rpcResponse{}, err
	}

	result := struct {
		Result struct {
			Json    json.RawMessage `json:"result"`
			Value   string          `json:"value"`
			Summary any             `json:"summary"`
		} `json:"result"`
		Error     json.RawMessage `json:"error"`
		Id        int             `json:"id"`
		Principal string          `json:"principal"`
		Version   string          `json:"version"`
	}{}

	err = json.Unmarshal(bytes, &result)
	if err != nil {
		return rpcResponse{}, err
	}
	if string(result.Error) != "null" {
		return rpcResponse{}, fmt.Errorf("%w: %s", errRpc, string(result.Error))
	}

	response := rpcResponse{
		Result:    result.Result.Json,
		Principal: result.Principal,
		Id:        result.Id,
		Version:   result.Version,
	}
	return response, nil
}

func (ipa *ipaIAMService) newRequest(method string, args []string, dict map[string]any) rpcRequest {

	id := ipa.id
	ipa.id++

	dict["version"] = ipa.version

	jmethod, _ := json.Marshal(method)
	jargs, _ := json.Marshal(args)
	jdict, _ := json.Marshal(dict)

	return fmt.Sprintf(`{
		"id": %d,
		"method": %s,
		"params": [
			%s,
			%s
		]
	}
	`, id, jmethod, jargs, jdict)
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("invalid blocksize")
	}
	if len(b) == 0 {
		return nil, errors.New("invalid PKCS7 data (empty or not padded)")
	}
	if len(b)%blocksize != 0 {
		return nil, errors.New("invalid padding on input")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errors.New("invalid padding on input")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errors.New("invalid padding on input")
		}
	}
	return b[:len(b)-n], nil
}

/*
e.g.

	"value" {
		"__base64__": "aGVsbG93b3JsZAo="
	 }
*/
type Base64EncodedWrapped []byte

func (b *Base64EncodedWrapped) UnmarshalJSON(data []byte) error {
	intermediate := struct {
		Base64 string `json:"__base64__"`
	}{}
	err := json.Unmarshal(data, &intermediate)
	if err != nil {
		return err
	}
	*b, err = base64.StdEncoding.DecodeString(intermediate.Base64)
	return err
}

func (b *Base64EncodedWrapped) MarshalJSON() ([]byte, error) {
	intermediate := struct {
		Base64 string `json:"__base64__"`
	}{Base64: base64.StdEncoding.EncodeToString(*b)}
	return json.Marshal(intermediate)
}

/*
e.g.

	"value": "aGVsbG93b3JsZAo="
*/
type Base64Encoded []byte

func (b *Base64Encoded) UnmarshalJSON(data []byte) error {
	var intermediate string
	err := json.Unmarshal(data, &intermediate)
	if err != nil {
		return err
	}
	*b, err = base64.StdEncoding.DecodeString(intermediate)
	return err
}

func (ipa *ipaIAMService) log(msg string) {
	if ipa.debug {
		log.Print(msg)
	}
}
