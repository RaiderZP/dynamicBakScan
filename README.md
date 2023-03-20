# dynamicBakScan
这是一款能根据访问的目录名称进行动态扫描的插件，具体扫描的思路如下：
![image](https://user-images.githubusercontent.com/38402326/226372028-bd60d716-7b5b-498d-9bed-24d23d5cac8e.png)
除了首个目录名以外，都会根据可能的备份习惯生成3个备份文件，通过对比是响应是否为200来判断是否存在备份信息

# 如何使用？
（1）创建一个存放备份后缀的文件在D:/dic/bak.txt中
![image](https://user-images.githubusercontent.com/38402326/226377429-1ddabe8d-547d-4ac1-b2fd-5970fea3c4b6.png)


（2）在burpsuite中导入该插件，在dynamicBakScan菜单页中输入测试域名白名单，可输入域名含有的关键字即可，多个域名可以用分号隔开，输入后，流量中存在该关键字的域名将自动的进行动态备份扫描
    例如，想要扫描www.baidu.com、以及www.alibaba.com域名，可将baidu;alibaba输入进白名单中，然后点击save
    ![image](https://user-images.githubusercontent.com/38402326/226374476-2ad6e4fc-4d25-4cf0-b2d4-3e608a8e2082.png)
    若想精确扫描某一子域名，输入完整的域名即可。
    
 （3）扫描出备份后，可在Issue中查看：
 ![image](https://user-images.githubusercontent.com/38402326/226375836-b19a72c7-c237-4c18-97fa-261fb086bbb9.png)

# 未来改善方向
  a.完善判断备份文件的精度，减少误报
  
  b.可在菜单中自定义后缀，无需导入文件
  
  c.增加文件动态扫描功能
