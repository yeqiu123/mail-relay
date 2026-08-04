# Mail Relay

用于批量管理 Outlook 邮箱并自动轮换 Microsoft OAuth 刷新令牌（Refresh Token）。

## 用户与数据隔离

管理员可在网页中添加、停用、重置密码或删除普通用户。每个用户只能查看、导入、导出和删除自己名下的邮箱及刷新记录；删除用户时会同步删除该用户的数据。管理员账号由 `.env` 中的 `APP_ADMIN_USERNAME` 和 `APP_ADMIN_PASSWORD` 管理。

## 数据格式

每行一个 Outlook 邮箱（四段格式）：

```text
email----password----client_id----refresh_token
```

密码、刷新令牌和访问令牌均使用 Fernet 加密后写入 SQLite。导出文件包含明文凭据，请妥善保管。

## 启动

1. 将 `.env.example` 复制为 `.env` 并设置真实密钥。
2. 执行 `docker compose up -d --build`。
3. 服务默认仅监听宿主机 `127.0.0.1:8765`，由 Nginx 提供公网 HTTPS。

网页不会定时重载邮箱列表。后台刷新服务会按设置周期（默认 7 天）轮换令牌并保存 Microsoft 返回的新刷新令牌。刷新令牌仍可能因撤销授权、修改密码、账号风控或 Microsoft 策略而失效，因此无法保证永久有效。
