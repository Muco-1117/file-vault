# File Vault

重复下载的安装包、聊天软件保存了几遍的附件、多个文件夹里的同一份资料，常常很难手动整理。File Vault 按文件大小和 SHA-256 找出内容完全相同的副本，生成可审阅的清单，再把选定副本移到带恢复日志的隔离目录。

**默认扫描只读；整理操作不永久删除文件。** 不需要注册、联网、数据库服务或第三方 Python 包。

## 快速开始

需要 Python 3.11+。在项目目录运行：

```powershell
python file_vault.py scan "D:\Downloads" --output downloads.plan.json
```

打开生成的 JSON 清单，检查每组的 `keep`（保留文件）、`duplicates`（隔离副本）、`size` 和 `sha256`。默认保留相对路径字典序最前的文件；若想保留另一份，可以交换 `keep` 和 `duplicates` 中的路径，保持校验值不变。

确认清单后执行：

```powershell
python file_vault.py apply downloads.plan.json --yes
```

终端返回恢复日志位置，例如：

```text
D:\Downloads\.file-vault\20261027T020000Z-a1b2c3d4\manifest.json
```

需要撤销整理时：

```powershell
python file_vault.py restore "D:\Downloads\.file-vault\20261027T020000Z-a1b2c3d4\manifest.json"
```

macOS/Linux 用相应路径替换上述 Windows 路径，例如 `~/Downloads`。

## 行为说明

- 比较文件内容，不按文件名、修改时间或扩展名猜测重复。
- 大小不同的文件不计算哈希，读取大文件时分块处理。
- 跳过空文件、硬链接、符号链接、`.git`、`node_modules`、`.venv`、`__pycache__` 和自身隔离目录。
- 执行前校验整个清单，文件已变更或路径越界时停止；移动前再次校验副本与保留文件。
- 在移动第一个文件前写入完整恢复日志。中断后可使用同一日志恢复；已恢复的日志再次执行不会重复操作。
- 恢复时校验隔离内容，目标位置已有新文件则拒绝覆盖。
- 输出清单已存在时拒绝覆盖，重新扫描请换一个文件名。

隔离区位于原目录内，因此整理后磁盘占用不会减少。输出的 `reclaimable_bytes` 表示重复副本的字节数；确认隔离内容不再需要后，可自行决定是否删除隔离目录。程序没有自动清空或永久删除命令。

## 使用边界

适用于个人静态文件夹的整理，不用于运行中的数据库、虚拟机、同步盘同步过程或应用正在写入的目录。整理或恢复期间请暂停其他程序对该目录的修改，校验与移动之间不是文件系统事务。

只识别字节完全一致的文件，不判断相似照片、不同编码文档或内容相近的压缩包。隔离移动保留文件本身的元数据，不迁移空目录。不要把包含个人文件路径的计划、恢复日志或隔离文件提交到公开仓库。

## 验证与结构

```powershell
python -m unittest discover -s tests -v
python -m py_compile file_vault.py
```

`file_vault.py` 包含扫描、清单执行和恢复功能；`tests/` 验证内容往返、变更拒绝、覆盖保护、路径边界和中断恢复。GitHub Actions 在 Windows/Linux 与 Python 3.11/3.13 上运行。

退出码：`0` 成功；`1` 扫描存在读取失败（仍生成清单）；`2` 参数、校验或文件操作失败。
