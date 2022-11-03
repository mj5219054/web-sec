# 红队工作日志

# 0x00 收集信息的方向

* 真实ip

* 子域名

* 同ip旁站

* c段

* 敏感目录

* 端口

* 股权分布，子公司

* dns同步数据库的域名

* 接口的收集

* cms指纹

# 0x01 收集资产的利用

* 真实ip（查找未授权或者端口爆破所能用到）

* 子域名（薄弱资产的，或者网站存在框架漏洞，或者逻辑漏洞）

* 同ip旁站（相同ip下的服务器，其他域名可能存在着漏洞）

* c段（碰到服务器群，可以看看同c段下的资产，是否能进入）

* 敏感目录（后台页面，未授权页面/.svn/.htacess等等）

* 端口（爆破/未授权）

* 股权分布，子公司（子公司的资产也是属于靶标的上的，但是需要有占有大部分股权）

* dns同步数据库的域名（可能回包会返回数据库所有数据）

* 接口的收集（今年某习通大事件，未授权）

* 指纹（nday）

# 0x02 收集方式

* 真实ip

* 绕cdn，dns解析记录，可能前期服务器没有上防火墙

* app或者小程序抓包

* 国外访问

* 子域名

* phpinfo.me，在线网站优势在于不会暴露自己的ip

* layer子域名挖掘机

* 御剑

* 同ip旁站

* 站长之家

* 其他在线网站

* c段    

* nmap

* masscan

* ping

* 敏感目录

* dismap

* railgon

* 御剑

* 端口

* nmap

* 在线端口爆破

* masscan误报会多

* goby

* 股权分布，子公司

* 爱企查

* 企查查

* 小蓝本

* dns同步数据库的域名

* 同子域名

* 接口的收集

0x00 信息收集方向

查看操作系统信息，内核版本

查看系统环境配置

查看进程

查看开放的端口

查看文本中包含关键词user、pass、admin、test、root等内容

查看网卡信息

查看arp历史记录

查看命令历史记录

查看登入历史记录

0x01 收集信息命令

查看操作系统信息，内核版本

#windows
ipconfig/all
systeminfo

#linux
ifconfig
uname -a
uname -mrs
dmesg | grep Linux
* 查看系统环境配置

# windows
env
set

# linux

* cat /etc/profile

* cat /etc/bashrc

* cat ~/.bash_profile

* cat ~/.bashrc
cat ~/.bash_logout
查看是否有打印机

lpstat -a
查看进程

#windows
tasklist
#linux
ps -ef
ps aux
top
ps -ef | grep root
强制杀进程

#windows
kill -F

#linxu
kill -s
* 查看开放的端口

#windows and linux
netstat -a #查看开启了哪些端口,常用netstat -an
netstat -n #查看端口的网络连接情况，常用netstat -an
netstat -v #查看正在进行的工作
netstat -p #协议名 例：netstat -p tcq/ip 查看某协议使用情况
netstat -s #查看正在使用的所有协议使用情况
netstat -antup
netstat -antpx
netstat -tulpn 
查看文本中包含关键词user、pass、admin、test、root等内容

#linux
grep -i user [filename]

grep -i pass [filename] 
查看网卡信息

#linux
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network
查看arp历史记录

arp -a
查看命令历史记录

* history
#关闭历史命令
* history +o
#开启历史命令
* history -o
#清除历史命令
* history -c 
查看登入历史记录
* ![图片](https://user-images.githubusercontent.com/79394963/199738017-87f177a6-0e4d-4b30-8fca-11ddf96ce316.png)
0x00 蜜罐简介

分析蜜罐的攻击数据包对研究攻击者的攻击为、提取攻击特征具有重要意义。诱骗攻击者扫描、攻击蜜罐可以有效拖延侵者对真实标的攻击进程，为防御者分析和反制争取宝贵时间。

0x01 蜜罐判别

1、web蜜罐，涉及到溯源操作，所以如果查看DevTools的话，可以看到很多对网站发起了请求（根据这一点，参考某些chrome 插件的原理）
2、web蜜罐，涉及到溯源操作，会对浏览器指纹进行获取，主要是canvas、字体之类的东西，可以通过插件hook掉一些api即可发现端倪
3、web蜜罐，毕竟是标准化产品，很多页面的真实性不够，比如一个论坛只有几个用户这种
4、日进web蜜罐后，发现数据库很干净、服务器很干净，那必然有鬼
5、4层服务蜜罐，基本没啥大的特征，最大的特征还是数据量不够，比如redis蜜罐里面没啥缓存、ftp蜜罐里面没啥文件等等

6、配置jsonp接口信息，仿站(提供目标站点扒取页面静态文件,功能无法正常使用)，二次修改后的源码(功能可用正常使用,但是所有数据全部为假数据,或者是精简以后的源码)

0x02  JSONP简介

1、什么是JSONP
JSONP（JSON with Padding）是JSON的一种”使用模式“，可用于解决主流浏览器的跨域数据访问的问题。
2、JSONP的实现原理
由于浏览器同源策略限制，网页无法通过Ajax请求非同源的接口数据。
script标签不受浏览器同源策略的影响，可以通过src属性，请求非同源的js脚本数据。通过函数调用的形式，接收跨域接口响应回来的数据。
3、实现JSONP
定义一个success回调函数。

<script>
    function success(data){
        console.log("获取到数据");
        console.log(data)
    }
</script>
0x00 蜜罐简介

分析蜜罐的攻击数据包对研究攻击者的攻击为、提取攻击特征具有重要意义。诱骗攻击者扫描、攻击蜜罐可以有效拖延侵者对真实标的攻击进程，为防御者分析和反制争取宝贵时间。

0x01 蜜罐判别

1、web蜜罐，涉及到溯源操作，所以如果查看DevTools的话，可以看到很多对网站发起了请求（根据这一点，参考某些chrome 插件的原理）
2、web蜜罐，涉及到溯源操作，会对浏览器指纹进行获取，主要是canvas、字体之类的东西，可以通过插件hook掉一些api即可发现端倪
3、web蜜罐，毕竟是标准化产品，很多页面的真实性不够，比如一个论坛只有几个用户这种
4、日进web蜜罐后，发现数据库很干净、服务器很干净，那必然有鬼
5、4层服务蜜罐，基本没啥大的特征，最大的特征还是数据量不够，比如redis蜜罐里面没啥缓存、ftp蜜罐里面没啥文件等等

6、配置jsonp接口信息，仿站(提供目标站点扒取页面静态文件,功能无法正常使用)，二次修改后的源码(功能可用正常使用,但是所有数据全部为假数据,或者是精简以后的源码)

0x02  JSONP简介

1、什么是JSONP
JSONP（JSON with Padding）是JSON的一种”使用模式“，可用于解决主流浏览器的跨域数据访问的问题。
2、JSONP的实现原理
由于浏览器同源策略限制，网页无法通过Ajax请求非同源的接口数据。
script标签不受浏览器同源策略的影响，可以通过src属性，请求非同源的js脚本数据。通过函数调用的形式，接收跨域接口响应回来的数据。
3、实现JSONP
定义一个success回调函数。

<script>
    function success(data){
        console.log("获取到数据");
        console.log(data)
    }
</script>
通过script标签，请求接口数据。

<script src="http://ajax.frontend.itheima.net:3006/api/jsonp?callback=success&name=silly&sge=20"></script>
4、JSONP的缺点
只支持GET数据请求，不支持POET数据请求。
JSONP与Ajax之间无任何关系，其没有用到XMLHttpRequest对象。

0x03 蜜罐工具

检测工具

https://github.com/iiiusky/AntiHoneypot-Chrome-simple
https://github.com/cnrstar/anti-honeypot
蜜罐部署

https://github.com/p1r06u3/opencanary_web
#hfish微步的蜜罐
https://hfish.net/?utm_source=baidu&utm_medium=sem&utm_campaign=HFish%20SEM&_channel_track_key=r1NHqJRj&plan=pinpailei&unit=pinpaici&keyword=HFish&e_creative=61242172991&e_keywordid=441052316215&e_keywordid2=441052316215&bd_vid=11248333029460957511#/
0x04 蜜罐实战

实战一：可以看到body中存在src网站的接口

图片

这时候已经有大量的数据包已经发出去了

实战二：非常正常的网页
0x05 蜜罐接口

qq接口
r.inews.qq.com/api/ip2city?otype=jsonp&_=1636958117616&callback=jQuery110206967149572043403&_1658332281840=

u.y.qq.com/cgi-bin/musicu.fcg?data={%22HG%22%3A{%22module%22%3A%22Base.VideoFeedsUrlServer%22%2C%22method%22%3A%22GetVideoFeedsUrl%22%2C%22param%22%3A{%22fileid%22%3A%220_11_013ee9171515dd784f7988b354084cf1a294299e.zip%22}}%2C%22DB%22%3A{%22module%22%3A%22ScoreCenter.ScoreCenterEx%22%2C%22method%22%3A%22free_login%22%2C%22param%22%3A{%22test%22%3A0%2C%22redirect%22%3A%22https%3A%2F%2Factivity.m.duiba.com.cn%2Fsubpage%2Findex%3FskinId%3D1049%22%2C%22activeId%22%3A0%2C%22activeType%22%3A%22%22}}%2C%22A%22%3A{%22module%22%3A%22CDN.SrfCdnDispatchServer%22%2C%22method%22%3A%22GetCdnDispatch%22%2C%22param%22%3A{%22guid%22%3A%22MS%22}}%2C%22B%22%3A{%22module%22%3A%22VipActivity.AwardPay%22%2C%22method%22%3A%22GetPayRank%22%2C%22param%22%3A{%22actid%22%3A%22D8D2CAAC126AE8FB%22%2C%22pagesize%22%3A0}}%2C%22C%22%3A{%22module%22%3A%22login.BasicinfoServer%22%2C%22method%22%3A%22CallBasicInfo%22%2C%22param%22%3A{}}}&callback=jsonp1658332281481

当当网
message.dangdang.com/api/msg_detail.php?customer_id=o4P00TweebicwjhS72NWew%3D%3D&data_type=jsonp&pageindex=1&module=1&pagesize=20&_=1596772198527&callback=jsonp1658332281478

cnblogs
passport.cnblogs.com/user/LoginInfo?callback=test

163接口
comment.api.163.com/api/v1/products/a2869674571f77b5a0867c3d71db5856/users/myInfo?callback=jsonp1658332281479

51cto
home.51cto.com/Index/getLoginStatus2015/reback/http%253A%252F%252Fwww.51cto.com%252F

https://home.51cto.com/index.php?s=/Index/getLoginStatus2015/reback/http%253A%252F%252Fwww.51cto.com%252F&xxoo=chrome-extension://

虎扑
remind.hupu.com/api/getRemindNum.api.php?contenttype=js&url=https%3A%2F%2Fbbs.hupu.com%2F40032955.html 

新浪
m.iask.sina.com.cn/cas/logins?domain=iask.sina.com.cn&popup=show&clsId=undefined&channel=null&businessSys=iask&fid=%22%3E%3Cscript%3Eeval(name)%3C/script%3E

https://login.sina.com.cn/sso/prelogin.php?entry=weibo&su=&rsakt=mod&client=ssologin.js(v1.4.19)&&callback=%3C%3E

人人
passport.game.renren.com/user/info?callback=jsonp1658332281480

csdn
api.csdn.net/oauth/authorize?client_id=1000001&redirect_uri=http://www.iteye.com/auth/csdn/callback&response_type=%22https%3A%2F%2Fapi.csdn.net%2Foauth%2Fauthorize%3Fclient_id%3D1000001%26redirect_uri%3D%22http%3A%2F%2Fwww.iteye.com%2Fauth%2Fcsdn%2Fcallback%26response_type%3D%22%3E%3Cimg%20src%3Dx%20onerror%3Deval(window.name)%3E

https://api.csdn.net/oauth/authorize?client_id=1000001&xxoo=chrome-extension://&redirect_uri=http://www.iteye.com/auth/csdn/callback&response_type=%22[url]https://api.csdn.net/oauth/authorize?client_id=1000001&redirect_uri=%22http://www.iteye.com/auth/csdn/callback&response_type=%22%3E%3Cimg%20src=x%20onerror=alert[/url](1)%3E

爱奇艺
nl-rcd.iqiyi.com/apis/urc/getrc?contenttype=js&agent_type=1&cb=cb_r0i8g&ckuid=&dp=3&limit=5&only_long=1&terminalId=11

58同城
employer.58.com/index/enterpriseinfo?&callback=jsonp1658332281482

https://employer.58.com/index/enterpriseinfo?&xxoo=chrome-extension://&&callback=jQuery152018637907672647902_1657807551290&_=1657807551747

passport.58.com/pso/viplogin?path=https://employer.58.com/

百度阅读
yuedu.baidu.com/nauser/getyduserinfo?na_uncheck=1&opid=wk_na&callback=bd

https://p.qiao.baidu.com/cps5/chat/push?sid=-100&tid=-1&reason=&tid_authtype=-1&sign ... ken%2522%253A%2522bridge%2522%257D&v=1657807497809587484

POST /abot/api/v1/tpl/commit HTTP/2
Host: sofire.baidu.com

CODED--v20ezLvhHO=QsO=Zau7]9gHbicHf1[2h`h7dDK9MoK9V]q3Y5cD^e_Db-W.d\dLe5;6aIT3gMS=T0C0X)T-ihJ6m0\5rao>uOWAL3Pzg-S+a;rspRz2jXhG],;.r\cQ/DgDIkqlVHOzQsOt[vW5^eW:yY/Ke0c<e5g6OjK)RYK.mMq=Z4W0Y)_*c,`My\K_p4DUaDz9eH7\^00AmP?Xc88-v,Gmm@@5,4g@IkSlSnPUa`XUn)`)rT[4]-k.g0c=ja3DIjylRnO=QsKtXPWBY)/*y0+9iIN2h`gSIkqlQXOzQsut[vW7]T[4]-[<a172qbpfIG\s^]jskr0OmUX3rhgziZh^a_t9vu09cjzGeMP+j`v<n`P`bVkzj001*KpBhbO=Y4Lyg7?tlLLQfTr)YWTXf,XnyppNvug@V3XlW7r7QPT<md4?\h,6][X\j0c<e5cEIkqlQXOzQsO2Uw+x]T[4]-[?a172i`g@IkG3MoupU\S,UwS@Y)/*ah_8a1_Me5;6MTKvMoK:Qsyt`dGEqh84mhNHd1[0gbO5Y3nxhL?/iM+r_dC?jh7zhl\/a^Soec34MUCxQY[>QQT=[wS4]zF8_hX_rph;,DVFMEGzQIK,U\LRmeX)j,KG`=[<e0N@e4C6MUilSnPvlQ\0o5+3\DS6wl0-z@O2ut88dT7mf76+a<L3Y4GyqXXCglK0rq/2h`gEOTK9MnOzQsS1Uw+@^)W4]-_>a172kdkDZEPpQoHoa;Tuea_Bi)c:cid0eA05iqp9ZXToQrO/a;[2[aPy]z[4]-_Ga172e4C6MkWlSnOpTLS2ZvWEYz[4]-_Ja172i`g@IkK7Moupl`?+nzGBrz[4]-_La172.tS?bn;6fnOzQsW0Uw+xthG3v0OJz0c<e5kEIkql]]H,jPvuee`-rCF7w\h2d_\`n4`vaXX6^]P?lP`?pPG4jXk4iZh^a_t9vu09coylPHO/UrSAU)\wr-_5wGl>yps2h`gGMzK9MzY;znam0rovx<i[*8wo:<5s>`g@IkO3MoupVPXxfdc5_hd-n-[=fKsCuth5N3G)QIXrbPc3ZQqBj)W9n\l1rm,2j4g@IkO4MoupYaL0nTc0aiT8v\k,lm_2h`gGNjK9Ms\*i;?/p?Bx\T[;b<_Ma5p>+OSCd36lPHO/WLSAUyh)s,d)v0[8a_l9,ttGLDDd]]Hti`?/XPPQsYT4njz;*`09uDg@IkSzMoupULS,Uw_5Y)/*],;.f]c2k4gDMkG)R-G7V][?YQO4]US8aYW<e][@ia_DMECzQIG,UMK0YQO4]US8aYW<e][@ia_DMECzQIG,UMq;YQT*j)y8aYcJg]tbjbxaMlS)Vo[9ZN[3YauA^fhVb-g=fIcKiE4dOVK9Vpi@U]K0YQO4]US8aYW<e][2h`gOMzK9MoK,Qr/tZQ_x_z[:],;.f]o2k4gENkW7Q-S8W]_3ZwODYz7*bYo.g0c@ha_6LDK3R,O=QsO,Y`35Yz7*bY+.g0dcvtl?bzy*QIK,UMO0Y`30\VC7y008z`_<p8tOc3PkgL[z\`Pu_dC?jh74a=y8a0?2jq_6OjLzPsLwa`B.ezT-jYg6mGO9a0?2jqc6OjKlPHO8UrSAUw[4]Yy9biW.d\cLj`gUIkClPHO8V\SAUwO0]T78],;.fms2k4gDIjylRYipWrS1XQO0]T78`YW8e\c<e5sSIkqlPHOzQsc0Uw+x]T[4]-o=a172i`g@Ik[*MoupULS,Uwg7Y)/*aX_8a1sLe5;6MDKvMoi,QsytYwO5_UW8aY[<e][@ia_6LDK6QXO=QsO,YP34\US4aX;<d][2h`gRNDK9^rLzk;_,Uwq@Y)0.ml<?rl?2jEw6On\kfMTsTLS>Z4WEj,X4wGk8a1+Oe5<:YXz+^X+pV1ut[zhwrY`-`X_Ke\cQv8d@c3WvMom-Qszxed47jd7*cY_.g4t1,el9LDK7Q,O=bvP,o?c0Y)yE]-3.e\c<e53RIkrp]\,/b\/tZaW5Y)/*glKGrp?0ptd7IF;WMKmnU]K.Yacx\T[DbY[.g0d>,Po4YY\ke\,oav0wUv3xj)_*c,_Hd1[0gbO5Y3nxhL?/iLutXPX*^z[Ix]`Hrl?2u5dFIkqlMn+pasP3Uw+xYz7*m-\/a17@h`h6MYSlSoGzQvS1mPWE]T7*m-\2a17@h`h6MXKlSoGzQvS1ozcx_)S4]-_GqlcQi`C6MkTlMoupQr/tYw`yY)/8`X_>f`k2k5_@IkK3^XO=UL/tYw`*Y)/8`X_>f`+2k5_@IkK3eHO=UL/tYw`-Y)/*],;.e1l:e5;6IjylQoX.baWt[vX-r,,C],;.e1l@e5;6IjylhMS-Qsy1ZwcC]9_Dcik?f1_Lh`hOc)KlSoK9V]q3Y5cD^e_Ecic8a5lCiDgUMDylhMS7Qsy1ZwcC]9_DcikGemcAh`hOc)[lSoK9V]q3Y5cD^e_Eaik8a5lCjDgUMDylhMS;Qsy0XPX?s9+*c-[Ifm/CiEsTNUS)QoKzQwz3Uw+x]T[4]14?e\cQe536LDLke,O=QrS,U)h)sz[I],_8a4hCe5;6MTKvMrL,QsytZa_C]T[4]1p1a172iDRDLkG5Mn+pkv>t[vW5Yz7*wHy.g0c@e4C6c4f9MoupULTDXPXwq8[I]-kGg][2h`h6IkqlSYm7VPc?Ydc5^USGn-p1qKcPiEgEM)fnQ-Tpb`[>e?hziCkDai,-eAcBjEwDMEW8RoG,VMO0YPW0Y-d8]-3.z`R2h`h<IkqlMn+pavut[vWC^*kCf.[>j]`bjqxdREO)SI_8Z^S=ZQSBa)c;cZgLi18bnENEIjylg,O=Qsr\eyP3s,zealk<o0c<e8WOIkqlVLTpS<[;ovG^afvVmkc<)2KupM4pd3PzgYnTlN,=a=`]]BS:uE<J*]sC-t?OeIfLh,?UasdYfQhQ\9\FvhO-n^?Oqud<TXXKZrLWUM`z]z_6_gk:hld4r2/L+E0vNVLKZ,zqaaS1aS[Dthz`_H\9yp4L.d0oWlj*^6\Sk]vMf)h*_XXZwG/>rIS;.ehvcmj\h,?`ku\N`UXiue`\x\<^fmp_hMxjK3fGQsTP\Ov)^yhebYzlyizbk^O6pa_ReYjpSZX9__nte),5j*GIu/lgl4<LgO0=a4HJXorxW_S2fzhSriv1`HpJzn@m+e/QN1;pS\7sY:TMb>d2e9dFvlz_rpt1iq3PNl7dSMX[la\-]),DfWuDkmz;nnh4o8cRb1m8[]HObM`?e=CV[D\VampMmal`suldaULI],?LmOvvocP,rX\Hi/k=modKnd0nOUHkYILO^MW2mQd.bCCZhEhHl]pQmO0GbV3PhMLU]^q?ZbXbs9v.x=hYn5`eoOoCaWHxjJm9V1_0o4FAi,\gb]`.*Jd>pDWrZ)Tre8ra\PX0`c`ArfG;j]lbgq4pvbsXfEGzjIrpVPO1Z5[6jeyGb0p-f1sBkql6NXK*SYPqU;dxZw[@Yz7*m<_Ma0c<e8c6OjKlPHPoi`[t[vW@^Uy8],;.q44Qe5<VfTylhnO=QsW.YPB5^z[4]1lGa172e9N\

easylearn.baidu.com/edu-web/activity/extracheck?courseId=1&xxoo=chrome-extension://&type=1&&callback=jQuery152023802138955832153_1658335948692&_=1658335949723 

zol
my.zol.com.cn/public_new.php

ipip
ipip.iask.cn/iplookup/search?format=js&_=1658332291360 


zdw.w8.com.cn/p.ht

直播吧
https://bbs.zhibo8.cc/user/userinfo?device=pc&xxoo=chrome-extension://&_=1657807551741&callback=%3C1

携程的
https://accounts.ctrip.com/ssoproxy/ssoGetUserInfo?xxoo=chrome-extension://&jsonp=%3C%22?&callback=11111

博客园(xss反弹)
https://wz.cnblogs.com/create?t=xxxx&xxoo=chrome-extension://&&u=%22%3E%3Csvg/onload=alert(%221%22)%3E&c=&i=0

虎牙的接口 
https://www.huya.com/udb_web/udbport2.php?m=HuyaLogin&xxoo=chrome-extension://&do=checkLogin

超星的
POST /getauthstatus HTTP/1.1
Host: passport2.chaoxing.com

enc=80a46477866993d3599b7f39506f8ece&uuid=ddbc623b7fc14a07b4b6c8cae881f51c

苏宁家的
https://myjr.suning.com/sfp/mutualTrust/getLoginInfo.htm?xxoo=chrome-extension://&&callback=jQuery172011468305000873791_1608255922695&_=1657807551743

爱问的
https://m.iask.sina.com.cn/cas/logins?domain=iask.sina.com.cn&xxoo=chrome-extension://&businessSys=iask&channel=null&popup=show&clsId=undefined&fid=1


京东的
https://api.m.jd.com/client.action?functionId=getBabelProductPaged&xxoo=chrome-extension://& ... 6e%6e%65%72%41%6e%63%68%6f%72%22%3a%22%22%7d&screen=2799*1208&client=wh5&clientVersion=1.0.0&sid=&uuid=&area=&_=1585823068850&callback=jsonp1

城通网盘
https://home.ctfile.com/iajax.php?item=profile&xxoo=chrome-extension://&action=index&jsonp=jQuery2398423949823

cnzz
s95.cnzz.com/z_stat.php?id=1261171181&web_id=1261171181 

zhibo8
bbs.zhibo8.cc/user/userinfo?device=pc&xxoo=chrome-extension://&_=1658335949723&callback=jQuery152023802138955832153_1658335948691

youku
download.youku.com/download

Ctf
home.ctfile.com/iajax.php?item=profile&xxoo=chrome-extension://&action=index&jsonp=jQuery2398423949823

Soho
v2.sohu.com/user/info/web?&xxoo=chrome-extension://&&callback=jQuery152023802138955832153_1658335948694&_=1658335949723


## 第一，没有安全的系统，只有不努力的帽子







