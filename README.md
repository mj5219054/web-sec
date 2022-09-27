# WEB 安全手册
<img src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg"> <img src="https://img.shields.io/github/stars/ReAbout/web-sec?style=social"> <img src="https://img.shields.io/github/forks/ReAbout/web-sec?style=social">

【声明】个人的快速查询目录，经验整理，仅供参考。     
【内容】包括个人对漏洞理解、漏洞利用、代码审计和渗透测试的整理，也收录了他人相关的知识的总结和工具的推荐。    

## 0x00 技能栈
依照红队的流程分工，选择适合自己的技能栈发展。    
>越接近中心的能力点越贴近web技术栈，反之亦然。可以根据自身情况，选择技术栈的发展方向。

![](./images/web-sec.png)
安全岗位的大体工作内容或职责

* 售后工程师：安全产品的售后服务工作，包括安全产品的交付实施、售后支撑、产品调试上架。比如客户买了咱们的防火墙，咱们要派人去安装调试吧，总不能让客户自己去安装吧。这是产品工程师或者售后工程师的主要工作内容。

* 售前工程师：主要是协助销售完成跟单，说的通俗易懂一点就是跟销售配合，一个做商务关系（吃吃喝喝、送礼请客）一个做技术方案（解决客户的痛点），两个人配合拿下项目。

* 渗透测试工程师：这个岗位是大多数人梦寐以求的，展现个人技术的时候到了。主要是模拟黑客对目标业务系统进行攻击，点到为止。

销售：不再赘述，估计你们年轻的人也不太关心，但是等你成长了，你就会发现，你以前的对销售的认知是多么的扯淡。

* 安全开发工程师：嗯，就是搞开发，要对安全也要了解，比如开发一个web应用防火墙，连web攻击都不懂，那还开发个啥，闭门造车啊，能防的注吗？

* 安全运维工程师：一个单位买了那么多安全产品，肯定要有人做运维的，分析一下日志，升级一下策略。定期检查一下业务系统的安全性，查看一下内网当中有没有威胁，这都是安全运维工程师要做的内容。

* 应急响应工程师：客户业务系统被攻击，要快速定位安全问题，要快速恢复业务系统，有的甚至还要取证报警。（家里如果被偷东西价值太大，你还不报警？心咋这么大）

等级保护测评师：按照国家要求，重要的业务系统需要按照安全等级进行保护的，目前国家已经发布了等级保护2.0标准，要按照这个标准进行建设。等级保护测评师的工作就是协助客户检查一下业务系统是否满足等级保护的要求，不满足的赶紧整改。

* ![图片](https://user-images.githubusercontent.com/79394963/192575016-4d7cf58d-4de6-48b6-a9e1-b871a0c8de0d.png)

* 安全服务工程师：好多企业把渗透测试工程师也归到安全服务工程师里面，无伤大雅。不懂安全服务，还不懂吃饭的服务员嘛，就是协助客户做好安全工作，具体的内容比如常见的漏洞扫描、基线检测、渗透测试、网络架构梳理、风险评估等工作内容。安全服务的面很大的，几乎涵盖了上述所有岗位的内容。

* ![图片](https://cdn.staticaly.com/gh/mj5219054/effective-potato@main/20220922/eddcd62c9201808b6d3b46710780cbcf.7gibqocaxt00.webp)

# 书单

* 微专业
Web安全微专业	Python应用基础	初级前端微专业	Java基础微专业	JavaWeb微专业

* 经典推荐
《互联网企业安全高级指南》	《企业安全建设指南：金融行业安全架构与技术实践》	《企业安全建设入门》
《白帽子讲Web安全》	《Web攻防之业务安全实战指南》	《代码审计：企业级Web代码安全架构》	《白帽子讲Web扫描》
《加密与解密（第4版）》	《Android应用安全防护和逆向分析》	《iOS应用逆向与安全》	《macOS软件安全与逆向分析》
《Python核心编程（第3版）》	《PHP和MySQL Web开发（原书第5版）》	《Java入门123：一个老鸟的Java学习心得》

* 企业安全建设
《互联网企业安全高级指南》	《企业安全建设指南：金融行业安全架构与技术实践》	《企业安全建设入门》
Web安全
《白帽子讲Web安全》	《Web攻防之业务安全实战指南》	《黑客攻防技术宝典 Web实战篇》	《Web前端黑客技术揭秘》
《黑客秘笈 渗透测试实用指南》
《SQL注入攻击与防御（第2版）》	《XSS跨站脚本攻击剖析与防御》

* 系统安全
《加密与解密（第4版）》	《木马核心技术分析》

* 移动安全
《Android应用安全防护和逆向分析》	《Android软件安全权威指南》	《Android软件安全与逆向分析》
《Android系统源代码情景分析（第三版）》	《Android安全攻防权威指南》
《macOS软件安全与逆向分析》	《iOS应用逆向与安全》	《iOS应用逆向工程 第2版》	《黑客攻防技术宝典 iOS实战篇》
代码审计
《代码审计：企业级Web代码安全架构》

* 安全研发
《白帽子讲Web扫描》	《Python 黑帽子》	《Python灰帽子》
编程入门
《Python核心编程（第3版）》	《PHP和MySQL Web开发（原书第5版）》
《Java入门123：一个老鸟的Java学习心得》	《Java Web从入门到精通（第2版）》

* 计算机与网络基础
《图解HTTP协议》	《HTTP权威指南》	《图解TCP/IP 第5版》
《鸟哥的Linux私房菜 基础学习篇 第四版》	《鸟哥的Linux私房菜：服务器架设篇（第三版）》

* 科技与人文
《黑客与画家》	《数学之美（第二版）》

* ![图片](https://user-images.githubusercontent.com/79394963/185969855-c0cdde70-1dae-437b-b84f-855055ed43b3.png)



## 0x01 漏洞理解篇(Vulnerability)
### 1.1 前端
> 同源策略 & CSP & JOSNP
- [跨域安全](./vul/VUL-CrossDomain.md)
### 1.2 后端
> 应用分层 & 漏洞分类
- [错综复杂的后端逻辑及安全](./vul/VUL-Backend.md)

### 1.3 打造自己的知识库
>爬取范围包括先知社区、安全客、Seebug Paper、跳跳糖、奇安信攻防社区、棱角社区
- [**[Tool]** 推送安全情报爬虫@Le0nsec](https://github.com/Le0nsec/SecCrawler)

## 0x02 漏洞利用篇(Exploit)
### 2.1 前端安全-XSS
> XSS 利用的是用户对指定网站的信任 
- [Cross Site Scripting (XSS)](https://github.com/ReAbout/web-exp/blob/master/exp/EXP-XSS.md)
 ### 2.2 前端安全-CSRF
> CSRF 利用的是网站对用户网页浏览器的信任   
- [Client-side request forgery (CSRF)](https://github.com/ReAbout/web-exp/blob/master/exp/EXP-CSRF.md)
###  2.3 SQL注入&数据库漏洞利用
- [SQL injection - MySQL](./exp/EXP-SQLi-MySQL.md)
- [SQL injection - Oracle](./exp/EXP-SQLi-Oracle.md)
- [SQL injection - MSSQL](./exp/EXP-DB-MSSQL.md)  
> MySQL，Oracle，MSSQL和PostgreSQL的OOB方法
- [SQL injection - 信息外带(OOB)](./exp/EXP-SQLi-OOB.md)

- [Redis 漏洞利用](./exp/EXP-DB-Redis.md)
- [**[Tool]** 数据库综合利用工具](https://github.com/Ryze-T/Sylas)
### 2.4 模板注入 Server Side Template Injection (SSTI)
> MVC架构中，模板参数恶意输入产生的安全问题
- [STTI 总述](./exp/EXP-SSTI-ALL.md)
- [SSTI -Python](./exp/EXP-SSTI-Python.md)
- [SSTI -PHP](./exp/EXP-SSTI-PHP.md)


### 2.5 命令注入&代码执行
- [命令注入&代码执行-PHP](./exp/EXP-CI-PHP.md)
- [命令注入&代码执行-Java](./exp/EXP-CI-Java.md)
### 2.6 Xpath注入
> XPath 即为 XML 路径语言
- [XPath Injection](./exp/EXP-XPath.md)
### 2.7 XML External Entity (XXE) 
- [XXE](./exp/EXP-XXE.md)
### 2.8 文件上传漏洞
- [文件上传漏洞](./exp/EXP-Upload.md)
### 2.9 Server-side request forgery (SSRF)
- [SSRF](https://github.com/ReAbout/web-exp/blob/master/exp/EXP-SSRF.md)

### 2.10 反序列化漏洞
>php,java只能序列化数据，python可以序列化代码。   
- [反序列化漏洞-PHP](./exp/EXP-PHP-Unserialize.md)
- [反序列化漏洞-Java](./exp/EXP-Java-Unserialize.md)
- [**[Tool]** 反序列化漏洞利用工具-Java ysoserial](https://github.com/frohoff/ysoserial)
> 拓展payload和添加脏数据绕过waf功能
- [**[Tool]** 反序列化漏洞利用工具 针对Java ysoserial进行拓展](https://github.com/su18/ysoserial)

### 2.11 包含漏洞
- [包含漏洞-PHP](https://github.com/ReAbout/web-exp/blob/master/exp/EXP-Include-PHP.md)

### 2.12 PHP-特性漏洞

### 2.13 Java-特性漏洞

- [表达式注入Java](./exp/EXP-Expression-Injection.md)

### 2.14 NodeJs-特性漏洞
- [Node.js 原型链污染](https://github.com/ReAbout/web-exp/blob/master/exp/EXP-nodejs-proto.md)
### 2.15 Other
> 利用前后DNS解析的不一致（劫持或者逻辑问题）   
- [DNS rebinding 攻击](./exp/EXP-DNS-Rebinding.md)
> 前后端不一致性
- [请求走私总结@chenjj](https://github.com/chenjj/Awesome-HTTPRequestSmuggling)
## 0x03 代码审计篇(Audit)

### 3.1 PHP
> vscode&phpstorm方案,xdebug2.X和xdebug3.X配置
- [PHP调试环境的搭建](./audit/AUD-PHP-Debug.md)
- [PHP代码审计@bowu678](https://github.com/bowu678/php_bugs)
### 3.2 JAVA
- [Java调试环境的搭建](./audit/AUD-Java-Debug.md)
- [Java代码审计@cn-panda](https://github.com/cn-panda/JavaCodeAudit)
- [Java安全@Y4tacker](https://github.com/Y4tacker/JavaSec)
- [Java漏洞平台@j3ers3](https://github.com/j3ers3/Hello-Java-Sec)

### 3.3 .NET
- [.Net反序列化@Ivan1ee](https://github.com/Ivan1ee/NET-Deserialize)

### 3.4 Perl CGI
> Perl CGI快速上手，了解Perl语言特性
- [Perl基础&代码审计@mi1k7ea](https://www.mi1k7ea.com/2020/11/24/Perl%E5%9F%BA%E7%A1%80-%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1/)

## 0x04 渗透篇(Penetration)
【流程】网络预置（信息收集）-->网络接入（外网突破）-->权限获取和提升-->权限维持（后门）-->后渗透    
【基础】---免杀+++反溯源+++协同---

### 4.0 环境准备
#### 4.0.1 代理
> 操作系统 on VM + OpenWrt网关 on VM = 全局跳板
- [全局代理[VMware]：Openwrt on VMware网关方案](./penetration/PEN-Openwrt.md)

> 全局代理，虚拟网卡，需要手动配路由
- [全局代理[Win]：Windows下socks客户端全局代理终极解决方案——tun2socks](./penetration/PEN-Tun2socks.md)

> SSTap全局代理也是基于虚拟网卡方案，可惜已停止更新，推荐使用1.0.9.7版本
- [**[Tool]** Windows下全局代理客户端工具 SSTap](https://github.com/solikethis/SSTap-backup)

>Proxifier 全局代理支持并不好，可以设置规则选择指定程序走代理或直连
- [**[Tool]** Windows下代理客户端工具 Proxifier](https://www.proxifier.com/)



### 4.1 网络预置
#### 4.1.1 常规信息
- [外网信息收集思路](https://github.com/ReAbout/web-exp/blob/master/penetration/PEN-Info.md)
#### 4.1.2 资产搜索引擎
- [fofa.so](https://fofa.so)   
- [shodan.io](https://www.shodan.io/)   
- [zoomeye.org](https://www.zoomeye.org/)
- [censys.io](https://search.censys.io/)
#### 4.1.3 移动端
>从移动端拓展目标信息
- [**[Tool]** 移动端信息收集工具 AppInfoScanner](https://github.com/kelvinBen/AppInfoScanner)    
- [**[Tool]** 安全分析框架 MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)


### 4.2 网络接入(exp)

#### 4.2.1 漏洞验证（扫描器）
> 工欲其善必先利器
##### 4.2.1.1 主动式
 - [**[Tool]** AWVS  Docker版](https://hub.docker.com/r/secfa/docker-awvs)
 - [**[Tool]** 长亭的扫描器 Xray](https://github.com/chaitin/xray)   
 - [**[Tool]** Vulmap](https://github.com/zhzyker/vulmap)   
 - [**[Tool]** 红队综合渗透框架SatanSword@Lucifer1993](https://github.com/Lucifer1993/SatanSword)   
##### 4.2.1.2 被动式
>将Burpusuite打造成一个被动式扫描器   
- [**[Tool]** BurpSutie 插件集合@Mr-xn](https://github.com/Mr-xn/BurpSuite-collections)  

#### 4.2.2漏洞利用(1day)
- [漏洞索引表]()【待整理】
> IoT安全 & web安全& 系统漏洞 1day整理
- [漏洞利用wiki](https://wiki.96.mk/)
- [红队中易被攻击的一些重点系统漏洞整理@r0eXpeR](https://github.com/r0eXpeR/redteam_vul)
- [织梦全版本漏洞扫描@lengjibo](https://github.com/lengjibo/dedecmscan)
- [**[Tool]** Struts2漏洞扫描&利用](https://github.com/HatBoy/Struts2-Scan)
- [**[Tool]** shiro反序列化漏洞利用](https://github.com/wyzxxz/shiro_rce_tool)

#### 4.2.3 字典

- [常用的字典，用于渗透测试、SRC漏洞挖掘、爆破、Fuzzing等@insightglacier](https://github.com/insightglacier/Dictionary-Of-Pentesting)
- [Fuzzing相关字典@TheKingOfDuck](https://github.com/TheKingOfDuck/fuzzDicts)

### 4.3 权限获取&提升
#### 4.3.1 Win
> 离线|在线|破解
- [Windows 认证凭证获取](./penetration/PEN-GetHash.md)  
- [**[Tool]** mimikatz Windows认证凭证提取神器](https://github.com/gentilkiwi/mimikatz) 
> 已经停止更新到CVE-2018
- [Windows提权漏洞集合@SecWiki](https://github.com/SecWiki/windows-kernel-exploits)
#### 4.3.2 Linux
- [Linux 认证凭证获取](./penetration/PEN-GetHash-Linux.md)
- [Linux setuid提权](./penetration/PEN-Setuid-Linux.md)
- [Linux 提权检测脚本 lse.sh](https://github.com/diego-treitos/linux-smart-enumeration)
> 已经停止更新到CVE-2018
- [Linux提权漏洞集合@SecWiki](https://github.com/SecWiki/linux-kernel-exploits)

#### 4.3.3 Docker&Sandbox逃逸

- [Dokcer容器逃逸@duowen1](https://github.com/duowen1/Container-escape-exps)

### 4.4 权限维持&后门
#### 4.4.0 通用
- [Meterpreter of Metasploit 使用教程](./penetration/PEN-MSF.md)
> backdoor生成，meterpreter操作指令
#### 4.4.1 Shell会话
- [反弹Shell & 升级交互式Shell (Linux&Win)](./penetration/PEN-ReShell.md)
#### 4.4.2 Webshell
- [**[Tool]** WebShell管理工具 菜刀](https://github.com/raddyfiy/caidao-official-version)
- [**[Tool]** WebShell管理工具 蚁剑](https://github.com/AntSwordProject/AntSword-Loader)
- [**[Tool]** WebShell管理工具 冰蝎](https://github.com/rebeyond/Behinder)
- [**[Tool]** WebShell管理工具 哥斯拉](https://github.com/BeichenDream/Godzilla)

#### 4.4.3 PC & Server
- [**[Tool]** Cobalt Strike ]()
- [Cobalt Strike资料汇总@zer0yu](https://github.com/zer0yu/Awesome-CobaltStrike)
#### 4.4.4 Mobile (Android & ios)  
### 4.5 免杀
- [免杀系列文章及配套工具@TideSec](https://github.com/TideSec/BypassAntiVirus)
### 4.6 隧道&代理
- [SSH 端口转发&开socks5](./penetration/PEN-ssh.md)
- [Iptables 端口复用](./penetration/PEN-Reuse.md)
 >FRP 客服端和服务端配合的端口转发工具
- [**[Tool]** 反向端口转发工具 FRP](https://github.com/fatedier/frp)
>Venom 可以嵌套多层代理，适合多层无外网的渗透测试，【停止更新】
- [**[Tool]** 内网多级代理服务端工具 Venom](https://github.com/Dliv3/Venom/releases)
>比Venom更加稳定，持续更新【推荐】
- [**[Tool]** 内网多级代理服务端工具 Stowaway](https://github.com/ph4ntonn/Stowaway)

- [**[Tool]** Windows版 proxychains](https://github.com/shunf4/proxychains-windows)
### 4.7 后渗透
#### 4.7.1 内网信息获取
>信息获取 & 远程文件操作 & 远程执行命令 & ipc$ & wmic & winrm
- [Windows 主机常用命令](./penetration/PEN-WinCmd.md)
> 可以提取流量中用户名&密码，NTML Hash，图片等，以及绘制网络拓扑。
- [**[Tool]** 流量取证工具 BruteShark](https://github.com/odedshimon/BruteShark)
> Windows rdp相关的登录记录导出工具。
- [**[Tool]** 浏览器数据导出解密工具](https://github.com/moonD4rk/HackBrowserData)
- [**[Tool]** SharpRDPLog](https://github.com/Adminisme/SharpRDPLog)
####  4.7.2 轻量级扫描工具
> 内网扫描神器，go语言跨平台，效率快，支持各类口令爆破，还有主机识别和web服务识别。
- [**[Tool]** fscan](https://github.com/shadow1ng/fscan)
> k8 team的内网扫描器
- [**[Tool]** Landon](https://github.com/k8gege/LadonGo)

#### 4.7.3 渗透框架
- [**[Tool]** 后渗透利用神器 Metasploit](https://www.metasploit.com/)
- [**[Tool]** 内网横向拓展系统 InScan](https://github.com/inbug-team/InScan)
- [**[Tool]** 开源图形化内网渗透工具 Viper](https://github.com/FunnyWolf/Viper)
#### 4.7.4 域渗透
- [域渗透@uknowsec](https://github.com/uknowsec/Active-Directory-Pentest-Notes)

#### 4.7.5 云平台
>通过accesskey获取相关主机权限执行命令
- [**[Tool]** Aliyun Accesskey Tool](https://github.com/mrknow001/aliyun-accesskey-Tools)

### 4.8 反溯源 

 - [Linux 痕迹清理](./penetration/PEN-LinuxClear.md)

### 4.9 协同
- [HackMD markdown协同工具(Docker版)](https://hackmd.io/c/codimd-documentation/%2Fs%2Fcodimd-docker-deployment)

###  在线工具和网站总结 

### 编码/加密

* CyberChef：编解码及加密，可本地部署 https://github.com/gchq/CyberChef

* OK Tools在线工具：https://github.com/wangyiwy/oktools

* CTF在线工具：http://www.hiencode.com/
* Unicode字符表：https://www.52unicode.com/enclosed-alphanumerics-zifu

* 在线MD5 Hash破解：https://www.somd5.com/

### 实用工具


* Explain Shell：Shell命令解析 https://explainshell.com/

* 在线正则表达式：https://c.runoob.com/front-end/854/

* Ceye DNS：DNS oob平台 http://ceye.io/

* DNS log：DNS oob平台 http://dnslog.cn/

* Webshell Chop：https://webshellchop.chaitin.cn/demo/

* XSS Chop：https://xsschop.chaitin.cn/demo/

* WebShell查杀：https://n.shellpub.com/

* Google Hacking Database：https://www.exploit-db.com/google-hacking-database

* Wayback Machine：网页缓存查询 https://archive.org/web

* 在线代码格式标准化：http://web.chacuo.net/formatsh

IP/域名收集

确认真实IP地址

* IP精准定位：https://www.ipuu.net/#/home

* IP 138：https://site.ip138.com/

* Security Trails：https://securitytrails.com/

多个地点Ping服务器


* Chinaz：https://ping.chinaz.com/

* Host Tracker：https://www.host-tracker.com/

* Webpage Test：https://www.webpagetest.org/

* DNS Check：https://dnscheck.pingdom.com/

Whois注册信息反查

* 站长之家 Whois：https://whois.chinaz.com/

* 中国万网 Whois：https://whois.aliyun.com/

* 国际 Whois：https://who.is/

DNS数据聚合查询

* Hacker Target：https://hackertarget.com/find-dns-host-records

* DNS Dumpster：https://dnsdumpster.com

* DNS DB：https://dnsdb.io/zh-cn

TLS证书信息查询

* Censys：https://censys.io

* Certificate Search：https://crt.sh

* 证书透明度监控：https://developers.facebook.com/tools/ct"

IP地址段收集

* CNNIC中国互联网信息中心：http://ipwhois.cnnic.net.cn

网络空间搜索

* Fofa：https://fofa.info/

* Shodan：https://www.shodan.io/

* ZoomEye：https://www.zoomeye.org/

* 谛听：https://www.ditecting.com/
360网络空间测绘：https://quake.360.cn/quake/#/index

威胁情报平台

* Virustotal：https://www.virustotal.com/gui/home/upload

* 腾讯哈勃分析系统：https://habo.qq.com/tool/index

* 微步在线威胁情报：https://x.threatbook.cn/

* 奇安信威胁情报：https://ti.qianxin.com/

* 360威胁情报：https://ti.360.net/#/homepage

* 安恒威胁情报：https://ti.dbappsecurity.com.cn/

* 火线安全平台：https://www.huoxian.cn

* Hacking8安全信息流：https://i.hacking8.com/

CTF平台

* CTF Wiki：https://ctf-wiki.org/

* CTF Time：https://ctftime.org/

* CTF Tools：https://github.com/zardus/ctf-tools

* 攻防世界：https://adworld.xctf.org.cn/

* Hacker 101：https://www.hacker101.com/

漏洞平台

* Exploit Database：https://www.exploit-db.com/

* HackerOne：https://www.hackerone.com/

* Vulhub：https://vulhub.org/

* 乌云镜像：http://wooyun.2xss.cc/

* 知道创宇漏洞平台：https://www.seebug.org/

靶机平台

* HackTheBox：https://www.hackthebox.com/

* OWASP Top10：https://owasp.org/www-project-juice-shop/

* WebGoat：https://github.com/WebGoat/WebGoat

公开知识库

* 狼组公开知识库：https://wiki.wgpsec.org/

* 404星链计划：知道创宇 404 实验室 https://github.com/knownsec/404StarLink

信息收集

指纹识别

* Wapplyzer：Chrome插件 跨平台网站分析工具 https://github.com/AliasIO/Wappalyzer

* TideFinger：提取了多个开源指纹识别工具的规则库并进行了规则重组 https://github.com/TideSec/TideFinger

* 御剑web指纹识别程序：https://www.webshell.cc/4697.html

* 云悉指纹识别：http://www.yunsee.cn/

扫描/爆破

* dirsearch：目录扫描/爆破 https://github.com/maurosoria/dirsearch

* dirmap：目录扫描/爆破 https://github.com/H4ckForJob/dirmap

* Arjun：HTTP参数扫描器 https://github.com/s0md3v/Arjun

* ksubdomain：子域名爆破 https://github.com/knownsec/ksubdomain

* Gobuster：URI/DNS/WEB爆破 https://github.com/OJ/gobuster

爆破字典

* Dictionary-Of-Pentesting：渗透测试、SRC漏洞挖掘、爆破、Fuzzing等常用字典 https://github.com/insightglacier/Dictionary-Of-Pentesting

* fuzzDicts：Web渗透Fuzz字典 https://github.com/TheKingOfDuck/fuzzDicts

* PentesterSpecialDict：渗透测试工程师精简化字典 https://github.com/ppbibo/PentesterSpecialDict

综合信息收集

* AlliN：https://github.com/P1-Team/AlliN

* Kunyu：https://github.com/knownsec/Kunyu

* OneForAll：https://github.com/shmilylty/OneForAll

* ShuiZe：https://github.com/0x727/ShuiZe_0x727

* Fofa Viewer：https://github.com/wgpsec/fofa_viewer

内网信息收集

* fscan：内网综合扫描工具 https://github.com/shadow1ng/fscan

* EHole：红队重点攻击系统指纹探测工具 https://github.com/EdgeSecurityTeam/EHole

* Ladon：用于大型网络渗透的多线程插件化综合扫描工具 https://github.com/k8gege/Ladon

### 漏洞研究

漏洞综述

* 未授权访问漏洞总结：http://luckyzmj.cn/posts/15dff4d3.html#toc-heading-3

漏洞挖掘

* Windows-Exploit-Suggester：https://github.com/AonCyberLabs/Windows-Exploit-Suggester

* Linux_Exploit_Suggester：https://github.com/InteliSecureLabs/Linux_Exploit_Suggester

开源漏洞库

* Vulhub：https://vulhub.org/

* PeiQi文库：http://wiki.peiqi.tech/

* PoCBox：https://github.com/0verSp4ce/PoCBox

* Vulnerability：https://github.com/EdgeSecurityTeam/Vulnerability

* POChouse：https://github.com/DawnFlame/POChouse

POC/EXP

* ysoserial：Java反序列化 https://github.com/frohoff/ysoserial

* Vulmap：漏洞扫描和验证工具 https://github.com/zhzyker/vulmap

* Some-PoC-oR-ExP：各种漏洞PoC、ExP的收集或编写 https://github.com/coffeehb/Some-PoC-oR-ExP

* CMS-Hunter：CMS漏洞测试用例集合 https://github.com/SecWiki/CMS-Hunter

* Penetration_Testing_POC：https://github.com/Mr-xn/Penetration_Testing_POC

内网渗透

Bypass

* PHPFuck：https://github.com/splitline/PHPFuck
* JSFuck：http://www.jsfuck.com/

Payloads

* PayloadsAllTheThings：https://github.com/swisskyrepo/PayloadsAllTheThings

* java.lang.Runtime.exec() Payload：java Payload在线生成 https://www.bugku.net/runtime-exec-payloads/

* PHP Generic Gadget Chains：PHP反序列化Payload https://github.com/ambionics/phpgg

WebShell

* Webshell收集项目：https://github.com/tennc/webshell

* 反弹shell命令速查：https://github.com/Threekiii/Awesome-Redteam

* Behinder 冰蝎：https://github.com/rebeyond/Behinder

* Behinder3：kali + java 11.0.14 或 windows10 + java 1.8.0_91，
注意，该环境下Behinder2无法正常运行
Behinder2：windows10 + java 1.8.0_91
Godzilla 哥斯拉：https://github.com/BeichenDream/Godzilla

内网穿透

* NPS：通过web端管理，无需配置文件 https://github.com/ehang-io/nps

* FRP：55k star项目 https://github.com/fatedier/frp

* Neo-reGeorg：tunnel快速部署 https://github.com/L-codes/Neo-reGeorg

* Proxifier：windows代理工具 https://www.proxifier.com/

* Proxychains：kali代理工具 https://github.com/haad/proxychains

容器逃逸

* CDK：容器渗透 https://github.com/cdk-team/CDK

其他

* The art of command line：快速掌握命令行 https://github.com/jlevy/the-art-of-command-line

* Responder：实现获取NTLM Hash等功能 https://github.com/SpiderLabs/Responder

* Impacket：其中的psexec.py通过用户名和密码远程连接到目标服务器 https://github.com/SecureAuthCorp/impacket

* PsTools：PsExec.exe功能同Impacket中的psexec.py https://docs.microsoft.com/en-us/sysinternals/downloads/pstools

移动端安全

* CrackMinApp：反编译微信小程序 https://github.com/Cherrison/CrackMinApp

* AppInfoScanner：移动端信息收集 https://github.com/kelvinBen/AppInfoScanner

安全厂商

安全厂商及其官网链接：https://github.com/Threekiii/Awesome-Redteam

Metasploit

Metasploit：https://github.com/rapid7/metasploit-framework

Cobaltstrike

* Awesome CobaltStrike：CobaltStrike知识库 https://github.com/zer0yu/Awesome-CobaltStrike

* Erebus：后渗透测试插件 https://github.com/DeEpinGh0st/Erebus

* LSTAR：综合后渗透插件 https://github.com/lintstar/LSTAR

* ElevateKit：提权插件 https://github.com/rsmudge/ElevateKit

Burpsuite

* HaE：高亮标记与信息提取辅助型插件 https://github.com/gh0stkey/HaE
* Log4j2Scan：Log4j主动扫描 https://github.com/whwlsfb/Log4j2Scan

Chrome crx

* 
Proxy SwitchyOmega：快速切换代理 https://github.com/FelisCatus/SwitchyOmega
* Wappalyzer：识别网站技术/框架/语言 https://www.wappalyzer.com/
* EditThisCookie：修改Cookie https://www.editthiscookie.com/

* FindSomething：在网页的源代码或js中寻找有用信息 https://github.com/ResidualLaugh/FindSomething
* Disable JavaScript：禁用JavaScript绕过弹窗 https://github.com/dpacassi/disable-javascript

* Hunter：查找网页暴露邮箱 https://hunter.io/chrome

Xray

* Xray：安全评估工具 https://github.com/chaitin/xray



#权限维持# #权限提升# #Linux# #Windows

* 权限提升思维图 https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques/blob/master/

* ![图片](https://user-images.githubusercontent.com/79394963/191659154-41a69033-2006-4456-bd71-69e15f156aea.png)












# 天下武功，无坚不破，唯快不破，以势赢者势颓则，以力胜者力尽则亡。


* ![图片](https://user-images.githubusercontent.com/79394963/188296267-d7a6cce7-c76e-47a1-8247-bd24b693d38c.gif)

* ![图片](https://user-images.githubusercontent.com/79394963/188296271-2a8e2e08-b532-4121-bbf2-ac64b875bde0.png)

