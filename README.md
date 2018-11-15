# traceroute
使用C语言实现traceroute功能，移植性较好，可以代码集成于项目中。
目前在linux、android平台（需要android交叉编译）经过测试，功能完善。

ps: mac平台系统头文件链接有问题，暂时先不管了~

```
/**
 * 主要功能函数
 * @param domain 测试的域名或者ip
 * @return traceroute的结果，格式为json
 */
char * traceroute_report(char * host);
```