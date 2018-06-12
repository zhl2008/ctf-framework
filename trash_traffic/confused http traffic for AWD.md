# confused http traffic for AWD

By Hence Zhang@Lancet



实现目标：

1.能够发送大量以假乱真的http攻击流量（payload的可信性：攻击性 重复性）

2.学习waf记录到的有威胁的流量，并进行重放（是否要加入此功能？ 是否要考虑加入通过流量自动化生成攻击脚本的功能）

3.向攻击脚本提供 trash traffic功能





基本思路：

1.使用mitmproxy记录流量；

2.通过随机数函数选定攻击的使用的：a.流量记录 b.攻击载荷 c.载荷参数 d.http头部等信息 

3.通过选定的上述内容生成最终的payload，每个线程将会对所有的主机逐个发送该payload，每个线程生成两种payload，payload数与线程数成正比