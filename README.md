# VMP_ODPlugin
VMProtect OD Plugin

Use to analyse vmp handlers and some other operations.


Analyse:       分析handler、入口的vmcode以及一些其他的基本信息。

Patch Hash：   调用一个自己写的ODScript，生成PatchHash后的文件（成功率未知。。）

To OEP：       到达OEP，并且处理一些Antidump（也是调用自己写的ODScript，成功率未知）

Fix API：      修复API，分某个地址和整个区段（在要修复的位置右键菜单）

Analyse code： 分析vmcode，需要输入esi（也就是vm_eip）

