#PYVPN

#通讯协议
两字节的包头区域 unsigned int,指示总长度
包体区域
    1字节报类型 unsigned int
    内容区域
一字节校验位

##认证协议
报类型 0 short int
1字节用户名长度
用户名
1字节密码长度
密码

Hbb