# Cobalt_Strike_CNA

## 0x01 CVE-2020-0796_CNA
在使用CobaltStrike上使用CVE-2020-0796提权

## 0x02 ReflectiveDllModules
### ExitService
一个在启动后会返回失败的服务程序，用于启动失败回调方式执行命令。
![](https://user-images.githubusercontent.com/21354684/124448044-96df4b00-ddb4-11eb-83ca-08d532638eb1.png)

### Service_Reflective_dll
使用系统服务进行权限维持的反射DLL模块，支持中文服务名、描述;支持设置SDDL;支持设置服务启动方式(自启、手动、触发、启动失败回调)。
