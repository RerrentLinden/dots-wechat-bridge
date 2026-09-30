# 更新、恢复与到期

## 每次检查

使用 `scripts/safe-status.py --state-dir runtime/state` 查看受控状态；工具 get_weixin_status 查看MCP实际可用性。检查systemd enabled/active/running、health/ready200、last_error、轮询时间、一个weixin.message订阅和发送终态。原始数据库、附件、QR、profile与日志保持私有。

## 更新

先在独立候选目录跑测试和schema检查。更新源码前确保没有sending/preparing。备份原源码并使用SQLite自身backup机制保存私有一致快照，保留当前state/secrets/profile。只停本服务，切换代码后启动，验证health/MCP/计数保留，再在既有插件设置刷新工具。服务暂停时读操作可重试；写操作始终用原稳定ID查状态。

单一state目录由worker.lock保护。systemd运行时不再启动第二个foreground或managed runtime。对服务做回滚时先检查新旧数据库/队列格式；旧版不能识别媒体字段时，不让它处理媒体待发记录。恢复代码不自动恢复旧数据库，以免丢失更新期间收到的消息。

## 错误分支

- context_required / fresh_inbound_required：等待本人新的微信来信提供有效context，不伪造或持久假定固定24小时TTL。原send_id保留。
- auth_required / -14：本人按login流程重新确认相同owner；身份改变拒绝。确认ready后保留原发送ID恢复。
- uncertain / delivery_unknown：可能已经发送，查询原ID并等待本人收件证据，不盲重发。重启中断sending也归为不确定；中断CDN准备可安全恢复有限重试。
- upload_expired / attachment_expired：7天媒体缓存已过期，获取本人新的文件；历史发送记录不改写为未发生。
- media_cache_full / queue_busy：等现有任务或TTL释放；不扩大内存/队列上限、不清空历史绕过。
- 订阅验证失败：核对产品实际callback的精确hostname和公开DNS，再更新allowlist；URL/签名不贴公开日志。订阅刷新由调用方负责。

## Runtime key

创建时记录表单实际到期时间。到期前本人创建替代专用runtime key（Tunnels Read+Use），在终端执行 `scripts/set-runtime-key.py --replace`，再只重启本服务。先验证新key连接正常和真实MCP读取，再按本人明确授权处理旧key。不要在聊天或命令参数里放secret，不先撤销仍在使用的key。

## 资源

保持模板unit的CPUQuota100%、MemoryHigh256MiB/MemoryMax384MiB、TasksMax64。读取本service cgroup的memory.current、memory.peak、memory.events；只有实际采样才能报告资源峰值。离线resource脚本是小样本，不是压力测试。整机重启、24小时闲置和极限文件仍应按自己的环境验收。

缓存TTL不清理消息数据库历史；依据自己的私有数据保留策略备份/清理。公开Issue只提供版本、固定错误类别和受控统计，不提供个人原文或完整state。
