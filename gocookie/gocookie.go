package gocookie

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os/user"

	// sqlite3 driver
	_ "github.com/mattn/go-sqlite3"
)

// interface cookier
type cookier interface {
	GetCookies(hostName string) (map[string][]byte, error)
}

// Chrome cookie
type chromeCookie struct {
	userDataPath, localStatePath, cookiePath string
}

func NewChromeCookie() cookier {
	return chromeCookie{}
}

func (c chromeCookie) GetCookies(hostName string) (map[string][]byte, error) {
	curUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("cannot confirmed current user, error: %v", err)
	}
	// chrome user data path
	c.userDataPath = curUser.HomeDir + `\AppData\Local\Google\Chrome\User Data`
	c.localStatePath = c.userDataPath + `\Local State`
	c.cookiePath = c.userDataPath + `\Default\Cookies`
	// get AES GCM Key
	key, err := c.getAESGCMKey(c.localStatePath)
	if err != nil {
		return nil, err
	}
	// connect Chrome's cookie db
	cookieDB, err := sql.Open("sqlite3", c.cookiePath)
	if err != nil {
		return nil, err
	}
	defer cookieDB.Close()
	// query with host name
	rows, err := cookieDB.Query("SELECT name,encrypted_value FROM cookies WHERE host_key LIKE ?", "%"+hostName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// get cookie value
	cookies := make(map[string][]byte)
	for rows.Next() {
		var name string
		var encryptedValue []byte
		err = rows.Scan(&name, &encryptedValue)
		if err != nil {
			return nil, err
		}
		prefix := encryptedValue[:3]
		var decryptedValue []byte
		if bytes.Equal(prefix, []byte{'v', '1', '0'}) || bytes.Equal(prefix, []byte{'v', '1', '1'}) {
			decryptedValue, err = decryptWithAESGCM(key, encryptedValue[3:15], encryptedValue[15:])
		} else {
			decryptedValue, err = decrypt(encryptedValue)
		}
		if err != nil {
			return nil, err
		}
		cookies[name] = decryptedValue
	}
	return cookies, nil
}

func (c chromeCookie) getAESGCMKey(localStateFilePath string) ([]byte, error) {
	localStateFile, err := ioutil.ReadFile(localStateFilePath)
	if err != nil {
		return nil, fmt.Errorf("read file failed, error: %v", err)
	}
	// deserialize json
	localState := make(map[string]interface{})
	err = json.Unmarshal(localStateFile, &localState)
	if err != nil {
		return nil, fmt.Errorf("deserialize json to map[string]interface{} failed, error: %v", err)
	}
	// decode
	encryptedKey, err := base64.StdEncoding.DecodeString(localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))
	if err != nil {
		return nil, fmt.Errorf("decode local state: os_crypt failed, error: %v", err)
	}
	if bytes.Equal(encryptedKey[:5], []byte{'D', 'P', 'A', 'P', 'I'}) {
		key, err := decrypt(encryptedKey[5:])
		if err != nil {
			return nil, fmt.Errorf("decrypt key failed, error: %v", err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("only support Chrome version >= v80")
}
