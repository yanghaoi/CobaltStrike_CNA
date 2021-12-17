# 0x01 简介
	    EasyPersistent,是一个用于windows系统上权限维持的Cobalt Strike CNA 脚本。
	    脚本整合了一些常用的权限维持方法，使用反射DLL模块可使用API对系统服务、计划任务等常见权限维持方法进行可视化操作（强烈建议使用白名单进程进行操作）。

## 脚本功能菜单：
![](https://i.loli.net/2021/07/02/TWnuefByhIG4pUz.png)

 - 设置常用路径
	 - 全局路径参数设置
 - 文件控制
	 - 文件属性、文件权限的查看和修改
	 - 文件符号链接的创建
 - 注册表
	 -  注册表的增加、删除、查询
 - 系统服务
	 - 系统服务的创建、查询、删除、SDDL设置
 - 用户操作
	 - 系统用户账户的添加、删除、修改、查询、克隆、激活、禁用
 - 启动目录
	 - 系统启动目录文件的查询、写入
 - 计划任务
	 - 计划任务的查询、写入、删除
 - DLL加载
	 - MSDTC服务、Explorer程序DLL劫持
 - BITS任务
	 - BITS任务的添加、查询、删除
 - WMI事件
	 - WMI事件订阅的添加、查询、删除

# 0x02 使用方法
	GUI界面参数根据理解填写，可能部分位置有Bug，欢迎提交issues.
## 示例

![](https://cdn.jsdelivr.net/gh/yanghaoi/Cobalt_Strike_CNA@latest/EasyCNA/img/Easy.gif)
## 文件控制
	主要是attrib、takeown、icacls、mklink几个命令的使用。
![attrib](https://i.loli.net/2021/07/02/roz3lRmSMKIPt9e.png)

![icacls](https://i.loli.net/2021/07/02/wkOAtBhsy2jdnUi.png)

## 注册表
	通过Reg命令执行操作，支持对以下位置进行操作：Run, RunOnce, RunOnceEx,Logon Scripts,Winlogon Shell, Winlogon Userinit
![添加Run键](https://i.loli.net/2021/07/02/lQxtfZ6BqNi3Hha.png)

	添加方法带有/f选项，可用于更新键值：
![](https://i.loli.net/2021/07/02/qD5mvLPWzVnYJMS.png)

	查询位置分为单个键查询和一键查询所有(选项里有的)启动项位置，查询所有比较暴力：
![](https://i.loli.net/2021/07/02/Tnf7q3Xe9gLi2oR.png)

	其他Tips:
	针对x86和x64注册表位置可使用下拉选项进行选择;
	使用时请注意HKLM和HKCU位置，x86和x64的不同;
	HKLM位置可能需要管理员权限，SYSTEM权限在写入HKCU位置会出现问题。

## 系统服务
### 系统服务主要使用SC命令和一些API进行操作
![添加服务](https://i.loli.net/2021/07/02/U5dmp2qBsInbkwY.png)

	脚本中提供了两个服务程序TransitEXE.exe和uinit.exe，其中uinit.exe为一个启动后会返回服务失败的程序，用于错误回调执行，TransitEXE.exe服务程序实现代码参考[CreateService](https://github.com/uknowsec/CreateService)，主要进行了以下修改：
 	1. 注释RC4加密部分
	2. 修改资源ID默认为100
	3. 增加互斥体检测退出服务功能
	4. 增加进程守护功能
	在ReflectiveDll的实现中，根据微软文档主要进行了以下功能开发：
 	1. 设置服务描述，设置多种启动类型添加，设置SDDL安全描述符
### 服务守护进程

![](https://cdn.jsdelivr.net/gh/yanghaoi/Cobalt_Strike_CNA@latest/EasyCNA/img/service.gif)
 
### 服务名称和显示名称在SCM中的位置
![](https://i.loli.net/2021/07/02/e98aHuMYl4T62NI.png)

	添加服务时，为了方便测试，脚本对一些参数进行字符随机化，并对各个流程进行了调试信息输出：
  
![](https://i.loli.net/2021/07/02/nldPAxI5v1TwCbr.png)

	添加服务后的显示：
 
![](https://i.loli.net/2021/07/02/Ttzg3VHwlNI2Gom.png)

	在这里，只需要选择一个二进制文件上传，点击添加即可，之后脚本会根据需要上传某个服务程序。如果是TransitEXE，反射DLL会将执行命令写入到服务程序资源信息中，随后启动服务，服务程序落地后启动后会提取出自身资源信息中的命令行，使用CreateProcess第二个参数来执行。

### 程序描述部分支持中文描述
![](https://i.loli.net/2021/07/02/T1sHqSUhfzmo4lp.png)

![](https://i.loli.net/2021/07/02/eYR7mjAtcMyuQqz.png)

### 触发器启动
	在命令行中的触发器使用了网络触发器：
``` cmd?linenums
sc triggerinfo ServiceName start/networkon
```
	API中使用的是硬件接口触发:
![](https://i.loli.net/2021/07/02/KBX6dTwJDbRa2Y3.png)

### 安全描述符设置
	在API中通过ConvertStringSecurityDescriptorToSecurityDescriptor和SetServiceObjectSecurity设置服务的安全描述符，如果进行一些限制设置需要SYSTEM权限(注意如果在administrator权限下设置了SDDL限制，那么会导致OpenService Failed的情况)：
![SDDL设置后无法操作服务](https://i.loli.net/2021/07/02/KAlwPI87nfqtaMQ.png)


### 服务启动失败回调
	启动服务失败后会有回调命令执行:
![服务启动失败回调命令执行](https://i.loli.net/2021/07/02/3b284j6vSRsPliX.png)


### 其他
	- 两个服务程序可以写成一个，只是uinit.exe是先写的；
	- 其他设置SDDL、修改服务、查询、删除部分功能没有完全强大，只能说是够用。
	- 脚本中默认的目录C:\360\不存在，会导致上传文件失败([-] could not upload file: 3)，可以修改默认目录，net helpmsg查询详细错误情况。

## 用户操作
### 查询用户：
	使用CS自带命令bnet()
  
![](https://i.loli.net/2021/07/02/eNvgYhQJ1HqF8xm.png)

### 添加用户:
	集成了CMD命令、API、参数欺骗。API添加和查询用户：
![](https://cdn.jsdelivr.net/gh/yanghaoi/Cobalt_Strike_CNA@latest/EasyCNA/img/AddUser_api.png)
	自带参数欺骗添加用户：
![](https://cdn.jsdelivr.net/gh/yanghaoi/Cobalt_Strike_CNA@latest/EasyCNA/img/AddUser.png)


### 克隆用户:
通过 <a href="https://github.com/yanghaoi/ridhijack">ridhijack</a>实现。

### 账户激活与禁用:
	这里的功能最初是为了激活Guest的，后面增加了不同组的添加、移除、账户激活禁用，主要就是使用api进行一些操作，然后我源码找不到了...:
  
![](https://i.loli.net/2021/07/02/rh1dPbFcVQfCp8I.png)

## 启动目录
	主要就是两个位置:
``` tex
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```
	程序可以写入到目录中进行自启动，但是不能设置隐藏属性。(一次测试不知道怎么搞的这个启动目录被搞成了其他位置C:\，启动后会弹出该目录下的文件夹，杀软会毫无反应。记录到了这个现象，还没进行深入研究。)

	在选项中可以设置远程文件名和执行方式，为直接上传和API重启写入:
  
![](https://i.loli.net/2021/07/02/LqA3kydp1BnDX8e.png)

	API重启写入利用函数MoveFile设置在重启后写入，可以绕过一些AV程序对启动目录的监控。

## 计划任务
	计划任务的操作可由SCHTASKS命令行和API来完成，由于命令行实现功能和API有差距(命令行无法设置描述和创建者)所以分开写了两个操作界面：
  
![](https://i.loli.net/2021/07/02/lnozb6sgk9SxADL.png)

### 通过命令行注册：
  
![](https://i.loli.net/2021/07/02/noROGcd5vCP8y39.png)

### 通过API注册：
  
![](https://i.loli.net/2021/07/02/a2LYiZPhTC1Gm64.png)


### 优化选项：
	 - 添加任务时未对文件是否存在进行判断,未增加文件上传选项；
	 - 命令行模式中的描述可以删除。
   
### 其他:
	 - API中使用\Everyone身份，如果没有已登录用户，可能导致启动失败。

## DLL加载
	利用msdtc服务加载oci.dll和Explorer加载linkinfo.dll原理进行DLL劫持，系统启动后可进行权限维持，通过禁用系统重定向不同位数下的system32目录进行了操作，方便简单：
### msdtc
![](https://i.loli.net/2021/07/03/WYnj4TCeqdAw8mo.png)

![](https://i.loli.net/2021/07/03/qiNfplJwCDnFE2s.png)

	注意：
	在64位系统中生成的DLL要是64位的才能执行，在CobaltStrike4.3中要勾选x64 payload，其他版本中64位DLL+ x86 Payload上线的是x86的rundll32.exe,x64payload上线的是x64的msdtc.exe。

	使用64位rundll32程序加载位于C:\windows\system32\下的32位dll,出错:
  
![](https://i.loli.net/2021/07/03/81rzaPtfOIvWXGn.png)

	那么使用C:\Windows\SysWOW64\rundll32.exe下的32位DLL加载C:\windows\system32\32.dll能成功吗？
  
![](https://i.loli.net/2021/07/03/uq2OQT6VU5LBPCj.png)

	可以看到也是不行的，猜测因为windows的重定向机制，使用32位程序时，系统会去找32位的system目录(SysWOW64)，把C:\windows\system32\32.dll复制到SysWOW64那就可以加载了：
  
![](https://i.loli.net/2021/07/03/jadmQ3v7uYiX1Jb.png)

	可以看到果然如此！

### Explorer
	会在用户登录后加载C:\windows\linkinfo.dll，同样需要与系统位数对应的DLL。

## Bitsadmin Jobs

	简单使用bitsadmin命令进行操作，据说仅适用于Windows7、8、Server 2008和Server 2012，还咩做实验。

## WMI事件订阅
	使用powershell脚本来进行WMI事件订阅设置。
	预置了6种触发方式：移动设备、用户登录、进程启动、时间间隔、某个时间、重启：
![](https://i.loli.net/2021/07/03/e4RbwHMU1CoDVli.png)

![](https://i.loli.net/2021/07/04/tCmEeL2Uw7cuqO1.png)

# 0x03 免责声明
 - 本项目实现中可能会对一些系统服务、底层API进行调用，实现过程中可能会导致系统异常，无法启动，请自行测试；
 - 本项目仅用于作者进行代码学习、系统研究等实验目的，作者不承担任何责任。

# 0x04 参考链接或源码
https://github.com/uknowsec/CreateService  
https://github.com/v1ncilazy/BypassAddUser  
https://github.com/An0nySec/ShadowUser  
https://github.com/Sw4mpf0x/PowerLurk  
