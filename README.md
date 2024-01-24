# 工程说明

## 工程简介
- 本工程通过调用openssl接口实现了SSL/TLS协议
- 使用的openssl版本为 openssl-1.1.1u
## 编译说明
- 创建build目录后在build目录执行以下命令
- **Windows**
    >- cmake -G "Visual Studio 14 2015" ..
    >- cmake --build ./ --config Release
- **Linux**
    >- sudo cmake ..
    >- sudo make
## 文件说明
- sslclient.cpp
    - ssl 客户端
- sslserver.cpp
    - ssl 服务端
- sslserver_concurrent.cpp
    - ssl 服务端并发模式