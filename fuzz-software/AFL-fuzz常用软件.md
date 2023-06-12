

## 软件概述

官网：libtiff.gitlab.io/libtiff

git仓库： https://gitlab.com/libtiff/libtiff

简介：**Libtiff** 是一个用来读写[标签图像文件格式](https://zh.wikipedia.org/wiki/标签图像文件格式)（简写为TIFF）的[库](https://zh.wikipedia.org/wiki/库)。

最新稳定版本	v4.3.0

git clone https://gitlab.com/libtiff/libtiff.git



## 编译安装

tif_ojpeg.c:907

## 测试图像

三种可以获得测试集的方法

https://lcamtuf.coredump.cx/afl/demo/

http://www.libtiff.org/images.html  

测试图像下载网站

https://download.osgeo.org/libtiff/old/





## afl-libtiff



###  下载解压

``` sh
git clone https://gitlab.com/libtiff/libtiff.git
```

### 插桩编译

1. afl-clang-fast 显示提示

2.  CC=/usr/local/bin/afl-clang-fast CXX=/usr/local/bin/afl-clang-fast++  ./configure --prefix=/home/wb/libtiff_llvm/tiff-4.3.0/build --disable-share--d

   > ### 导入环境变量仅当前命令行/控制台可用
   >
   > **在当前命令行/控制台中直接使用export定义环境变量** **作用域：当前命令行**

3. make

4. make install

5. build文件中显示bin文件夹

### 测试用例

1. 下载测试用例

   ``` sh
   wget https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz
   ```

   

2. 最小化测试用例

   ``` sh
   afl-cmin -i testcase_full -o testcase_cmin ./tools/tiff2pdf @@ /dev/null
   
   ```

3. 开始fuzz

   ``` sh
   afl-fuzz -i testcase_cmin/ -o afl_output/ tools/tiff2pdf @@ /dev/null
   ```
   




------

## AFL-lrzip

>  用afl的llvm模式 对 lrzip 软件进行插桩编译 

### 软件github地址

https://github.com/ckolivas/lrzip.git

### Download

```sh
git clone git://github.com/ckolivas/lrzip.git
```

查看软件目录，发现没有`configure`文件也没有`cmake`，但是有`autogen.sh`  ,很多软件使用autogen 脚本生成configure脚本

### make前提知识：

==开发提供 configure.ac 及 Makefile.am文件, 剩下的一切都交由 autogen.sh 处理.==

一般需要先安装auto工具

``` sh
sudo apt-get install autoconf automake libtool 
```

运行流程：

> 1. 运行 **autogen.sh** 脚本文件，生成 configure 脚本文件；
> 2. 运行 **configure** 脚本文件，检查系统环境，配置编译选项（并生成 Makefile 文件）；
> 3. 运行 **make** 命令，执行代码的构建操作；
> 4. 运行 **make install** 命令，安装编译生成的文件。

如果是`autogen.sh`脚本，则先执行一下脚本，生成configure脚本。

### 对于有`configure`的包常规流程如下：

``` sh
# 进去包根目录
mkdir build && cd build
sudo ../configure # 会在build下生成makefile
make # 调用makefile
sudo make install # 把lib、bin等加到系统对应目录下
```



### 实战

``` sh
#安装过程中可能会提示安装相关依赖，按照提示install即可
./autogen.sh  # 先生成configure文件
#在configure阶段  用选项指定编译器路径和要安装的路径
#先afl-clang-fast 查看一下路径，如下：
#CC=/usr/local/bin/afl-clang-fast ./configure
#CXX=/usr/local/bin/afl-clang-fast++ ./configure

#这里不知道为什么使用llvm模式编译失败，所以换成afl的gcc / g++
CC=/usr/local/bin/afl-gcc CXX=/usr/local/bin/afl-g++  ../configure
#如果make失败后，重新执行上述命令，需要先make clean
```



------



## AFL-openjpeg

> 用afl的llvm模式 对 openjpeg 软件进行插桩编译 

### 软件github地址

https://github.com/uclouvain/openjpeg.git

### Download

``` sh
git clone git://github.com/uclouvain/openjpeg.git
```

 进入软件发现是用`cmake`构建工具

### `cmake`前提知识：

> 市面上有很多Make工具，遵循这不同的规范和标准，导致Makefile格式也不太一样。所以较难实现跨平台
>
> 而cmake 针对上面问题设计，不依赖特定编译器，配置文件：CMakeList.txt ，定制整个编译流程，然后再根据目标用户的平台进一步生成所需的本地化 Makefile 和工程文件

### 使用cmake生成Makefile 并编译流程

1. 编写 CMake 配置文件 CMakeLists.txt 。
2. 执行命令 `cmake PATH` 或者 `ccmake PATH` 生成 Makefile（`ccmake` 和 `cmake` 的区别在于前者提供了一个交互式的界面）。其中， `PATH` 是 CMakeLists.txt 所在的目录。如果CMakeLists在当前目录下，一般用   `cmake ./`    在cmake时，可指定编译器 `cmake .. -DCMAKE_CXX_COMPILER=/usr/local/gcc/bin/g++`  (具体问题需要更换编译器)
3. 使用 `make` 命令进行编译。

### 实战

1. 首先在下载好的软件包中创建一个build文件夹，然后进入。

   ``` sh
   # cmake 以及make会生成很多编译的中间文件和makefile文件，所以创建一个文件专门用来编译
   #进去包根目录
   mkdir build && cd build
   # 指定编译器 afl-clang-fast 可以看LLVM模式CC CXX的提示路径
   cmake -DCMAKE_CXX_COMPILER=/usr/local/bin/afl-clang-fast++ -DCMAKE_C_COMPILER=/usr/local/bin/afl-clang-fast ../
   make #调用一个makefile
   sudo make install
   ```

   



## ASAN

``` sh
#导入环境变量
export CC=/usr/local/bin/afl-clang-fast
export CXX=/usr/local/bin/afl-clang-fast++
export CFLAGS="-g -O0 -fsanitize=address"
export CXXFLAGS="-g -O0 -fsanitize=address"
```



``` sh
#普通安装
./configure --prefix=/home/wb/fuzz/gpac-putong/gpac/build --static-mp4box  
make -j 50

```

``` sh
$ ./MP4Box -version                                                                                                    
MP4Box - GPAC version 1.1.0-DEV-rev1574-g8b22f0912-master
(c) 2000-2021 Telecom Paris distributed under LGPL v2.1+ - http://gpac.io
        MINI build (encoders, decoders, audio and video output disabled)

Please cite our work in your research:
        GPAC Filters: https://doi.org/10.1145/3339825.3394929
        GPAC: https://doi.org/10.1145/1291233.1291452

GPAC Configuration: --prefix=/home/wb/fuzz/gpac-putong/gpac/build --static-mp4box
Features: GPAC_CONFIG_LINUX GPAC_64_BITS GPAC_HAS_SOCK_UN GPAC_MINIMAL_ODF GPAC_HAS_QJS GPAC_HAS_FREETYPE GPAC_HAS_JPEG GPAC_HAS_PNG  GPAC_DISABLE_3D 
```



[](https://github.com/xiao-benben/xiao-benben.github.io/blob/master/pocs/poc1.zip)



## 参考：

[1]: https://zhuanlan.zhihu.com/p/92318861	"多种编译安装方式"
[2]: https://www.giantbranch.cn/2020/08/25/%E4%BD%BF%E7%94%A8afl%E6%9D%A5fuzz%20libtiff/	"fuzz教程"

[3]: https://www.hahack.com/codes/cmake/	"CMake入门实战"

