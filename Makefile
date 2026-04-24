.PHONY: help setup install build run test clean dev frontend-install frontend-build browser-deps stop

# 默认目标
help:
	@echo "Any Auto Register - Makefile"
	@echo ""
	@echo "可用命令:"
	@echo "  make setup          - 创建并激活 Conda 环境"
	@echo "  make install       - 安装后端依赖"
	@echo "  make browser-deps  - 安装浏览器依赖 (playwright + camoufox)"
	@echo "  make frontend-install - 安装前端依赖"
	@echo "  make frontend-build - 构建前端"
	@echo "  make build         - 安装所有依赖并构建前端"
	@echo "  make dev           - 开发模式 (后端 + 前端分开运行)"
	@echo "  make run           - 启动后端服务"
	@echo "  make stop          - 停止后端服务"
	@echo "  make test          - 运行测试"
	@echo "  make clean         - 清理构建产物"

# 创建 Conda 环境
setup:
	@echo "创建 Conda 环境 any-auto-register (Python 3.12)..."
	@conda create -n any-auto-register python=3.12 -y
	@echo "请运行: conda activate any-auto-register"

# 安装后端依赖
install:
	@echo "安装后端依赖..."
	@pip install -r requirements.txt

# 安装浏览器依赖
browser-deps:
	@echo "安装 Playwright Chromium..."
	@python -m playwright install chromium
	@echo "安装 Camoufox..."
	@python -m camoufox fetch

# 安装前端依赖
frontend-install:
	@echo "安装前端依赖..."
	@cd frontend && npm install

# 构建前端
frontend-build:
	@echo "构建前端..."
	@cd frontend && npm run build

# 完整构建: 环境 + 依赖 + 前端
build: setup install browser-deps frontend-install frontend-build
	@echo "构建完成!"

# 开发模式: 先安装依赖，然后启动后端和前端开发服务器
dev: install browser-deps frontend-install
	@echo "开发模式准备完成!"
	@echo "终端 1: make run  (启动后端)"
	@echo "终端 2: cd frontend && npm run dev  (启动前端开发服务器)"

# 启动后端
run:
	@echo "启动后端服务..."
	conda run -n any-auto-register python main.py

gen:
	conda run -n any-auto-register python  scripts/register_chatgpt_accounts.py --count 400 --mode access_token_only

rescue:
	conda run -n any-auto-register python  scripts/rescue*.py --limit 400
sync:
	conda run -n any-auto-register python  scripts/sync*.py

# 停止后端服务
stop:
	@echo "停止后端服务..."
	@-pkill -f "python main.py" 2>/dev/null || true
	@-pkill -f "uvicorn" 2>/dev/null || true
	@-lsof -ti:8000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8889 | xargs kill -9 2>/dev/null || true
	@echo "服务已停止"

# 运行测试
test:
	@echo "运行测试..."
	@python -m pytest tests/ -v

# 清理构建产物
clean:
	@echo "清理构建产物..."
	@rm -rf frontend/dist
	@rm -rf frontend/node_modules
	@rm -rf build dist *.egg-info
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "清理完成"
