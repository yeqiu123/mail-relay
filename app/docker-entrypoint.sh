#!/bin/sh

# 邮件正文、令牌数据库及运行期临时文件仅允许容器账户访问。
umask 077
data_dir="${DATA_DIR:-/data}"
if [ -d "$data_dir" ]; then
  chmod 700 "$data_dir"
  find "$data_dir" -maxdepth 1 -type f -name 'mail-relay.db*' -exec chmod 600 {} \;
  if [ -d "$data_dir/backups" ]; then
    chmod 700 "$data_dir/backups"
    find "$data_dir/backups" -maxdepth 1 -type f -exec chmod 600 {} \;
  fi
fi
exec "$@"
