// Copyright 2025 Versity Software
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
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const IpaVersion = "2.254"

type IpaIAMService struct {
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

var _ IAMService = &IpaIAMService{}

func NewIpaIAMService(rootAcc Account, host, vaultName, username, password string, isInsecure, debug bool) (*IpaIAMService, error) {
	ipa := IpaIAMService{
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
		return nil, fmt.Errorf("cookie jar creation: %w", err)
	}

	mTLSConfig := &tls.Config{InsecureSkipVerify: isInsecure}
	tr := &http.Transport{
		TLSClientConfig: mTLSConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	ipa.client = http.Client{Jar: jar, Transport: tr}

	err = ipa.login()
	if err != nil {
		return nil, fmt.Errorf("ipa login failed: %w", err)
	}

	req, err := ipa.newRequest("vaultconfig_show/1", []string{}, map[string]any{"all": true})
	if err != nil {
		return nil, fmt.Errorf("ipa vaultconfig_show: %w", err)
	}
	vaultConfig := struct {
		Kra_Server_Server             []string
		Transport_Cert                Base64EncodedWrapped
		Wrapping_default_algorithm    string
		Wrapping_supported_algorithms []string
	}{}
	err = ipa.rpc(req, &vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("ipa vault config: %w", err)
	}

	cert, err := x509.ParseCertificate(vaultConfig.Transport_Cert)
	if err != nil {
		return nil, fmt.Errorf("ipa cannot parse vault certificate: %w", err)
	}

	ipa.kraTransportKey = cert.PublicKey.(*rsa.PublicKey)

	isSupported := slices.Contains(vaultConfig.Wrapping_supported_algorithms, "aes-128-cbc")

	if !isSupported {
		return nil,
			fmt.Errorf("IPA vault does not support aes-128-cbc. Only %v supported",
				vaultConfig.Wrapping_supported_algorithms)
	}
	return &ipa, nil
}

func (ipa *IpaIAMService) CreateAccount(account Account) error {
	return fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) GetUserAccount(access string) (Account, error) {
	if access == ipa.rootAcc.Access {
		return ipa.rootAcc, nil
	}

	req, err := ipa.newRequest("user_show/1", []string{access}, map[string]any{})
	if err != nil {
		return Account{}, fmt.Errorf("ipa user_show: %w", err)
	}

	userResult := struct {
		Gidnumber []string
		Uidnumber []string
	}{}

	err = ipa.rpc(req, &userResult)
	if err != nil {
		return Account{}, err
	}

	uid, err := strconv.Atoi(userResult.Uidnumber[0])
	if err != nil {
		return Account{}, fmt.Errorf("ipa uid invalid: %w", err)
	}
	gid, err := strconv.Atoi(userResult.Gidnumber[0])
	if err != nil {
		return Account{}, fmt.Errorf("ipa gid invalid: %w", err)
	}

	account := Account{
		Access:  access,
		Role:    RoleUser,
		UserID:  uid,
		GroupID: gid,
	}

	session_key := make([]byte, 16)

	_, err = rand.Read(session_key)
	if err != nil {
		return account, fmt.Errorf("ipa cannot generate session key: %w", err)
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, ipa.kraTransportKey, session_key)
	if err != nil {
		return account, fmt.Errorf("ipa vault secret retrieval: %w", err)
	}

	req, err = ipa.newRequest("vault_retrieve_internal/1", []string{ipa.vaultName},
		map[string]any{"username": access,
			"session_key":   Base64EncodedWrapped(encryptedKey),
			"wrapping_algo": "aes-128-cbc"})
	if err != nil {
		return Account{}, fmt.Errorf("ipa vault_retrieve_internal: %w", err)
	}

	data := struct {
		Vault_data Base64EncodedWrapped
		Nonce      Base64EncodedWrapped
	}{}

	err = ipa.rpc(req, &data)
	if err != nil {
		return account, err
	}

	aes, err := aes.NewCipher(session_key)
	if err != nil {
		return account, fmt.Errorf("ipa cannot create AES cipher: %w", err)
	}
	cbc := cipher.NewCBCDecrypter(aes, data.Nonce)
	cbc.CryptBlocks(data.Vault_data, data.Vault_data)
	secretUnpaddedJson, err := pkcs7Unpad(data.Vault_data, 16)
	if err != nil {
		return account, fmt.Errorf("ipa cannot unpad decrypted result: %w", err)
	}

	secret := struct {
		Data Base64Encoded
	}{}
	json.Unmarshal(secretUnpaddedJson, &secret)
	account.Secret = string(secret.Data)

	return account, nil
}

func (ipa *IpaIAMService) UpdateUserAccount(access string, props MutableProps) error {
	return fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) DeleteUserAccount(access string) error {
	return fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) ListUserAccounts() ([]Account, error) {
	return []Account{}, fmt.Errorf("not implemented")
}

func (ipa *IpaIAMService) Shutdown() error {
	return nil
}

// Implementation

const requestRetries = 3

func (ipa *IpaIAMService) login() error {
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

	var resp *http.Response
	for i := range requestRetries {
		resp, err = ipa.client.Do(req)
		if err == nil {
			break
		}
		// Check for transient network errors
		if isRetryable(err) {
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		return fmt.Errorf("login POST to %s failed: %w", req.URL, err)
	}
	if err != nil {
		return fmt.Errorf("login POST to %s failed after retries: %w",
			req.URL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return errors.New("cannot login to FreeIPA: invalid credentials")
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("cannot login to FreeIPA: status code %d",
			resp.StatusCode)
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

func (ipa *IpaIAMService) rpc(req rpcRequest, value any) error {
	err := ipa.login()
	if err != nil {
		return err
	}

	res, err := ipa.rpcInternal(req)
	if err != nil {
		return err
	}

	return json.Unmarshal(res.Result, value)
}

func (ipa *IpaIAMService) rpcInternal(req rpcRequest) (rpcResponse, error) {
	httpReq, err := http.NewRequest("POST",
		fmt.Sprintf("%s/ipa/session/json", ipa.host),
		strings.NewReader(req))
	if err != nil {
		return rpcResponse{}, err
	}

	ipa.log(fmt.Sprintf("%v", req))
	httpReq.Header.Set("referer", fmt.Sprintf("%s/ipa", ipa.host))
	httpReq.Header.Set("Content-Type", "application/json")

	var httpResp *http.Response
	for i := range requestRetries {
		httpResp, err = ipa.client.Do(httpReq)
		if err == nil {
			break
		}
		// Check for transient network errors
		if isRetryable(err) {
			time.Sleep(time.Second * time.Duration(i+1))
			continue
		}
		return rpcResponse{}, fmt.Errorf("ipa request to %s failed: %w",
			httpReq.URL, err)
	}
	if err != nil {
		return rpcResponse{},
			fmt.Errorf("ipa request to %s failed after retries: %w",
				httpReq.URL, err)
	}

	defer httpResp.Body.Close()

	bytes, err := io.ReadAll(httpResp.Body)
	ipa.log(string(bytes))
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
		return rpcResponse{}, fmt.Errorf("%s: %w", string(result.Error), errRpc)
	}

	return rpcResponse{
		Result:    result.Result.Json,
		Principal: result.Principal,
		Id:        result.Id,
		Version:   result.Version,
	}, nil
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	if err, ok := err.(net.Error); ok && err.Timeout() {
		return true
	}

	if opErr, ok := err.(*net.OpError); ok {
		if sysErr, ok := opErr.Err.(*syscall.Errno); ok {
			if *sysErr == syscall.ECONNRESET {
				return true
			}
		}
	}

	return false
}

func (ipa *IpaIAMService) newRequest(method string, args []string, dict map[string]any) (rpcRequest, error) {

	id := ipa.id
	ipa.id++

	dict["version"] = ipa.version

	jmethod, errMethod := json.Marshal(method)
	jargs, errArgs := json.Marshal(args)
	jdict, errDict := json.Marshal(dict)

	err := errors.Join(errMethod, errArgs, errDict)
	if err != nil {
		return "", fmt.Errorf("ipa request invalid: %w", err)
	}

	request := map[string]interface{}{
		"id":     id,
		"method": json.RawMessage(jmethod),
		"params": []json.RawMessage{json.RawMessage(jargs), json.RawMessage(jdict)},
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	return string(requestJSON), nil
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

func (ipa *IpaIAMService) log(msg string) {
	if ipa.debug {
		log.Println(msg)
	}
}
