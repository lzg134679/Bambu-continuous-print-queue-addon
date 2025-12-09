# 拓竹连续队列打印系统

- 一个用于拓竹3D打印机的自动化打印队列管理系统，需要有homeassistant和自动换盘，支持通过FTP上传文件、Home Assistant集成，并自动生成连续打印自动化配置。
- https://www.bilibili.com/video/BV1Tm2vBcE6j/?share_source=copy_web&vd_source=235f7e0190ffb5dfaf2098f46ea150bf

## 功能特性

### 核心功能
- **文件管理**：上传、下载、删除3MF文件，支持本地和远程文件浏览
- **FTP集成**：与打印机FTP连接，支持FTPS加密传输
- **队列管理**：拖拽排序打印队列，支持多份打印配置
- **自动化生成**：自动生成Home Assistant自动化配置，实现连续打印

## 系统需求

- Python 3.8+
- 拓竹3D打印机（有换盘组件，打印机系统版本不能有mqtt通讯加密或新版本打开局域网模式使用）
- Home Assistant（必须，用于自动化功能，可以在B站搜索windows环境的homeassistant一键端）
- 网页浏览器

## 安装步骤

### 1. 克隆项目
- 克隆项目

### 2. 创建虚拟环境（推荐）
```bash
# Windows
python -m venv venv
venv\Scripts\activate

### 3. 安装依赖
```bash
pip install -r requirements.txt
```

## 快速开始

### 1. 运行应用（本机运行）
```bash
python app.py
```
应用将自动打开浏览器，访问 http://127.0.0.1:5000

### 2. 使用 Docker Compose 运行（无 Home Assistant 加载项商店时推荐）

在项目根目录已提供 `docker-compose.yaml`，确保本机已安装 Docker 和 Docker Compose，然后执行：

```bash
docker compose up -d --build
```

启动完成后，在浏览器访问：`http://你的主机IP:5000`（本机可访问 `http://127.0.0.1:5000`）。

容器会将数据和配置保存在当前目录下的 `data/` 文件夹中，打印文件默认使用当前目录下的 `3mf/` 文件夹（可直接在宿主机中管理 3MF 文件）。

### 3. 配置设置
1. 点击左下角"⚙️ 配置"按钮
2. 填入以下信息：

#### FTP配置
- **主机地址**：打印机IP地址
- **FTP端口**：默认990（FTPS）
- **用户名**：通常为 `bblp`
- **密码**：打印机的局域网访问码
- **路径**：A1mini默认为 `/cache`

#### Home Assistant配置
- **URL**：Home Assistant地址（例如 http://192.168.1.100:8123）
- **Token**：长期访问令牌（在Home Assistant中生成）
- **打印机实体**：打印机实体ID（例如 a1mini_xxxxxxxxxx）

3. 点击"测试连接"验证配置是否正确

### 4. 上传和打印文件

#### 方式一：上传本地文件
1. 网页中会自动列出3mf文件夹内的3mf文件
2. 配置好任务后文件会自动上传到打印机

#### 方式二：选择打印机文件
1. 在"打印机文件"区域浏览打印机文件
2. 选择文件后下一步会自动下载对应文件到项目临时目录

### 5. 配置打印队列
配置每个文件的打印参数：
- 打印次数
- 打印顺序
- 准备选项
- 耗材选择

## 配置文件说明

`config.ini` 包含以下配置项：

```ini
[ftp]
host = 192.168.1.100      # 打印机IP
port = 990                # FTP端口
user = bblp               # 用户名
password = password       # 局域网访问码
path = /cache             # 默认路径

[homeassistant]
url = http://192.168.1.100:8123    # Home Assistant地址
token = eyJ......                  # 长期访问令牌
printer_entity = a1mini_xxxxxx     # 打印机实体ID
notify_entity = text.xxxxx         # HA中自定义text实体，打印完成后触发更新此text实体，不配置不触发更新
ams_count = 4                      # AMS数量（默认最大为4不需要更改，会自动适配实际数量）
```

## 常见问题

### Q: 连接FTP时出现超时错误
**A**: 检查以下几点：
1. 打印机IP地址是否正确
2. 打印机和电脑是否在同一局域网

### Q: Home Assistant自动化不工作
**A**: 请确保：
1. Home Assistant地址和令牌正确
2. 打印机实体ID正确（在Home Assistant中查看）
3. Home Assistant和打印机的网络连接稳定

### Q: 上传大文件时很慢
**A**: 这是正常的，拓竹大部分打印机无线文件传输都很慢，我的A1mini上传100K/s，下载200K/s

### Q: 如何生成Home Assistant长期令牌？
**A**: 
1. 登录Home Assistant
2. 点击左下角用户头像 → 安全
3. 向下滚动找到"长期访问令牌"
4. 点击创建新令牌并复制

## 贡献指南


欢迎拉取和提交问题

