## Done Log

### Platform and Deployment
- [x] Bare Ubuntu bootstrap for Docker/Git/SSH and app env/secrets provisioning in `scripts/bootstrap-ubuntu.sh`
- [x] GitHub SSH helper for private repository mode in `scripts/setup-github-ssh.sh`
- [x] Scheduled pull-based update and rebuild via `scripts/auto-update.sh` + `scripts/setup-auto-update.sh`
- [x] Safe rollback on failed deploy/update via `scripts/healthcheck-stack.sh`, `scripts/deploy-prod.sh`, `scripts/auto-update.sh`
- [x] Deployment history log in `logs/deploy-history.log` with admin dashboard visibility

### Security and Secrets
- [x] File-based secrets support (`APP_SECRET_KEY_FILE`, `ADMIN_PASSWORD_FILE`) wired in app config and preflight
- [x] Sensitive-data repository scanner in `scripts/audit-sensitive.sh`
- [x] Optional generated bootstrap admin password report in `scripts/bootstrap-ubuntu.sh`

### Admin/User Functionality
- [x] Registration approval flow and admin-driven user/admin creation
- [x] User block/unblock/delete actions in Admin -> Users
- [x] Live online users, system metrics, and combined WG+Xray per-user traffic monitoring
- [x] Service health dashboard with container states and modal logs
- [x] User cabinet improvements: profile card/edit modal and device setup card

### UI/UX
- [x] Section organizer tabs with active highlighting
- [x] Modal create-user flow and improved admin actions feedback
- [x] Simplified recommended free clients per platform with one-click install links

### Quality and CI
- [x] Smoke test one-command runner `scripts/test-smoke.sh`
- [x] FastAPI startup migration from `@app.on_event` to lifespan
- [x] CI checks workflow `.github/workflows/ci-checks.yml` (sensitive audit + smoke tests)
- [x] Keep both deployment modes: local and production







- [x] Приложение адаптировано для мобильных устройств: динамическая адаптация контента и поддержка поворота экрана
- [x] Добавлено переключение в ночную цветовую схему



- [x] В страницу About добавлена информация об авторстве, правах и лицензии
- [x] Добавлена MIT лицензия и ссылки на лицензию в приложении
- [x] Добавлен автор приложения в футер с контактом Telegram: https://t.me/Dmitry_as_Solod

- [x] Панель администратора разгружена: контент разделен на дочерние блоки (sub-tabs) внутри основных разделов
