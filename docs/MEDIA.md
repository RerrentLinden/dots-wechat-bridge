# 私有媒体工具契约

完整机器 schema：[`mcp-schema.json`](mcp-schema.json)。全部操作继承已认证、专用且只由本人使用的 MCP Tunnel 访问边界。没有公网文件上传端口或任意目标收件人参数。

## 出站

1. 在调用方实际执行环境读取文件，计算 byte size 和小写 whole SHA256；最大20MiB。路径/URL不能代替实际文件字节。
2. `begin_weixin_upload(upload_id,filename,kind,size,sha256)`：kind=image/file。调用方 upload_id 为稳定的1..128字符字母/数字/下划线/连字符。后续步骤使用**返回的 up_... ID**。
3. `upload_weixin_chunk(upload_id,offset,data_base64,chunk_sha256)`：原始块1..65536B，从offset0顺序上传。核对响应 next_offset、offset、accepted_size。相同字节的重试返回duplicate=true；冲突、缺块、越界拒绝。不要向聊天打印base64。
4. `finalize_weixin_upload(upload_id)`：检查完整大小/whole SHA256；图片需可解析且<=800万像素。只有status=ready可发送；status=error不是成功。
5. `get_weixin_status` 取得 latest_owner_message_id，再 `read_weixin_message` 验证。`send_weixin_media(send_id,upload_id,message_id)` 只给该owner；上传完成后立刻读取最新peer context_token。
6. 返回真正media_... send_id，用它查询 `get_weixin_send_status`。一份上传最多承诺一个发送，重试相同send_id安全；不要换ID重复发送。

`get_weixin_upload_status(upload_id)` 查询进度、hash、到期和关联send_id。begin阶段只预留磁盘缓存预算，不分配整文件内存。每块只校验当前块；whole scan在finalize和发送准备各一次。

| 主状态 | 解释 |
|---|---|
| queued | 排队、CDN准备或正在发送；还没有API接受证据 |
| accepted | 腾讯消息API正常接受；delivered仍为null |
| error | 确定拒绝、过期、需要本人重新认证或需要新来信上下文 |
| uncertain | 消息POST可能已经成功；保留ID，不自动重发 |

transport_status保留原细节：preparing/sending/context_required/auth_required/rejected/delivery_unknown。context/auth错误属于需要新来信或本人认证的恢复分支；确定限流最多3次。CDN准备失败可有限重试，因为尚未发出消息；消息POST网络不确定不能按CDN重试规则处理。

## 入站

`read_attachment_chunk(message_id,attachment_id,offset,length)` 的 length为1..65536。data_base64仅在structuredContent中，content.text不含二进制。重组时校验ID、range、total_size和whole SHA256。图片工具返回image/jpeg预览，去除EXIF，原始bytes仍在私有缓存。

媒体缓存共享128MiB、TTL7天；过期需本人重发。出站保留私有源文件并在终态清除AES/CDN引用。无网络公开下载地址、无整文件base64或ASR。
