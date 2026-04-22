ida 9.3绿色脚本

## 环境
  - 1.cmake
  - 2.vcpkg
  - 3.RapidJSON
  - 4.Boost
  - 5.OpenSSL
  - 6.c++23

## 目录结构
```
.
├── CMakeLists.txt
├── README.md
├── src/
│   └── main.cpp                          # C++ 主程序
├── scripts/
│   └── all_platform_93_idakeygen.py      # 跨平台 Python 版 keygen
└── data/
    ├── licenses.json                     # license 模板（输入）
    └── idapro.hexlic                     # 生成的 license 示例（输出）
```

## 构建与运行
```sh
cmake -B cmake-build-debug
cmake --build cmake-build-debug
cd cmake-build-debug && ./idac
```
程序会读取 `../data/licenses.json`，并在当前工作目录写出 `idapro.hexlic`。
