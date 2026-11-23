# Cookie 同步

一套自托管的 Cookie 同步方案：Chrome 扩展负责上传和同步当前网站的 Cookie，Cloudflare Worker + D1 负责云端存储与管理面板。

## 一、部署后端（Cloudflare Worker）

1. 在 Cloudflare 创建一个 D1 数据库。
2. 创建一个 Worker，把 worker.js 的内容粘贴进去并部署。
3. 在 Worker 的「绑定」中添加 D1 数据库绑定，变量名必须是：cookie_sync_db。
4. 在 Worker 的「变量和机密」中添加：
   - UUID（机密）：路径前缀，建议使用随机 UUID，例如 3f2a…，它就是访问地址的一部分。
   - S_PW（机密）：登录密码，请使用强密码。
   - URL_302（变量，可选）：非法访问时跳转的地址，默认是 https://www.google.com。
5. 数据库表和索引会在第一次请求时自动创建（CREATE TABLE IF NOT EXISTS 与 CREATE INDEX IF NOT EXISTS），无需手动执行 SQL。schema.sql 仅作参考。

管理面板地址：https://你的Worker域名/你的UUID/

面板功能：
- 按域名、备注、Cookie 名称实时筛选。
- 勾选记录，支持全选、反选、取消选择和批量删除（删除前有二次确认）。
- 新增、编辑、删除单条记录，值默认隐藏，点击可显示。
- 深色与浅色主题切换，设置会保存在浏览器中。

## 二、安装扩展

1. 打开 chrome://extensions，开启右上角的「开发者模式」。
2. 点击「加载已解压的扩展程序」，选择 extension 文件夹。
3. 点击扩展图标，填写项目地址（形如 https://你的Worker域名/你的UUID）和密码 S_PW，点击「测试连接并保存」。

注意：extension 目录中必须包含 icon-16.png、icon-48.png、icon-128.png 三个 PNG 文件，manifest.json 已引用它们（icons 与 action.default_icon）。缺少任一文件，Chrome 将无法载入扩展。

## 三、日常使用

- 上传当前 Cookie：在需要保存登录状态的网站上打开弹窗，填写备注（用于区分同一网站的不同账号，如「主号」「小号」），点击「上传当前 Cookie」。上传会覆盖云端该备注下的旧记录，完成后自动刷新云端列表。
- 同步到浏览器：点击「同步到浏览器」，或在云端记录卡片上点击对应账号的「同步到浏览器」。同步会逐条写入 Cookie，并回读校验，结果会显示成功数量、失败原因和回读确认数量，然后刷新页面。
- 连接成功后，弹窗会自动拉取当前域名的云端记录。
- 高级设置（折叠区）：可手动刷新域名缓存，或退出登录（仅清除密码，保留项目地址）。

## 四、Cookie 写入规则

扩展在写入 Cookie 时遵循 Chrome 扩展 API 的要求：

- HostOnly 的 Cookie 不传 domain 参数；非 HostOnly 的 Cookie 才传 domain。
- __Host- 前缀的 Cookie 必须 Secure、path 为 /，且不传 domain。
- __Secure- 前缀的 Cookie 必须 Secure。
- SameSite 为 None 的 Cookie 必须 Secure。
- 会话 Cookie 不传 expirationDate；已过期的 Cookie 会被跳过并计入结果。
- 写入时带上当前标签页的 storeId（多容器或隐私窗口场景）。
- 每条都检查 chrome.runtime.lastError 和返回值，并在写入后读回校验，不会在失败时显示成功。

## 五、安全说明

- 请妥善保管 S_PW 和 UUID，任何拿到它们的人都能读取云端 Cookie。
- Cookie 值以明文保存在 D1 中，请只在你自己的 Cloudflare 账号中使用。
- 扩展不记录、不显示 Cookie 值，后台服务只定时刷新域名列表。
- 浏览器中的密码保存在 chrome.storage.local 中。

## 六、文件说明

- worker.js：Cloudflare Worker 后端与管理面板。
- schema.sql：数据库表结构参考（程序会自动建表）。
- extension/manifest.json：扩展清单。
- extension/popup.html、popup.css、popup.js：弹窗界面与逻辑。
- extension/background.js：后台服务，每 12 小时刷新域名缓存。


## License

This project is released under the [MIT License](./LICENSE). Copyright (c) 2026 Jiong-Vip.

You may use, copy, modify, merge, publish, distribute, sublicense, and sell copies of this software, provided the copyright notice and permission notice are included in all copies or substantial portions. The software is provided "AS IS", without warranty of any kind.
