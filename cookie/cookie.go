package cookie

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"os/user"

	"github.com/donkw/gocookie/cryption"
	// sqlite3 driver
	_ "github.com/mattn/go-sqlite3"
)

// Cookie cookie struct
type Cookie struct {
	HostName       string
	Name           string
	Value          string
	EncryptedValue []byte
}

// GetChromeCookiesString get chrome's cookie string with host name
func GetChromeCookiesString(hostName string) (string, error) {
	cookies, err := GetChromeCookies(hostName)
	if err != nil {
		return "", err
	}
	var cookieString string
	cLen := len(cookies)
	for i := 0; i < cLen; i++ {
		cookieString += (cookies[i].Name + "=" + cookies[i].Value)
		if i < cLen-1 {
			cookieString += ";"
		}
	}
	return cookieString, nil
}

// GetChromeCookies get chrome's cookie array with host name
func GetChromeCookies(hostName string) ([]Cookie, error) {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("get current system user info fail, error: %+v", err)
	}
	// chrome user data path
	userDataPath := currentUser.HomeDir + `\AppData\Local\Google\Chrome\User Data`
	// chrome local state file path
	localStatePath := userDataPath + `\Local State`
	// chrome cookie file path
	cookiePath := userDataPath + `\Default\Cookies`

	key, err := getChromeAESGCMKEY(localStatePath)
	if err != nil {
		return nil, err
	}

	// open chrome's cookie database
	cdb, err := sql.Open("sqlite3", cookiePath)
	if err != nil {
		return nil, err
	}
	defer cdb.Close()

	// query with host name
	rows, err := cdb.Query("SELECT name,encrypted_value FROM cookies WHERE host_key LIKE ?", "%"+hostName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// loop and get cookie value
	var cookies []Cookie
	for rows.Next() {
		var cookie Cookie
		err = rows.Scan(&cookie.Name, &cookie.EncryptedValue)
		if err != nil {
			return nil, err
		}

		prefix := cookie.EncryptedValue[:3]
		var decryptedValue []byte
		if bytes.Equal(prefix, []byte{'v', '1', '0'}) || bytes.Equal(prefix, []byte{'v', '1', '1'}) {
			decryptedValue, err = cryption.DecryptWithAESGCM(key, cookie.EncryptedValue[3:15], cookie.EncryptedValue[15:])
			if err != nil {
				return nil, err
			}
		} else {
			decryptedValue, err = cryption.Decrypt(cookie.EncryptedValue)
			if err != nil {
				return nil, err
			}
		}
		cookie.Value = string(decryptedValue)
		cookies = append(cookies, cookie)
	}
	return cookies, nil
}

func getChromeAESGCMKEY(localStateFilePath string) ([]byte, error) {
	localStateFile, err := ioutil.ReadFile(localStateFilePath)
	if err != nil {
		return nil, err
	}

	localState := make(map[string]interface{})
	err = json.Unmarshal(localStateFile, &localState)
	if err != nil {
		return nil, err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState["os_crypt"].(map[string]interface{})["encrypted_key"].(string))
	if err != nil {
		return nil, err
	}

	if bytes.Equal(encryptedKey[0:5], []byte{'D', 'P', 'A', 'P', 'I'}) {
		key, err := cryption.Decrypt(encryptedKey[5:])
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, err
}
