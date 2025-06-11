#!/bin/bash

echo "🔍 检查并修复 .gitmodules 文件..."

cat > .gitmodules <<EOF
[submodule "emp-tool"]
	path = emp-tool
	url = https://github.com/emp-toolkit/emp-tool.git

[submodule "emp-ot"]
	path = emp-ot
	url = https://github.com/emp-toolkit/emp-ot.git

[submodule "external/mcl"]
	path = external/mcl
	url = https://github.com/herumi/mcl.git
EOF

echo "✅ .gitmodules 文件已写入完成。"

echo "🔄 同步并初始化所有子模块..."
git submodule sync
git submodule update --init --recursive

echo "✅ 所有子模块已更新完成。"

# 检查是否存在 CMakeLists.txt
if [ ! -f external/mcl/CMakeLists.txt ]; then
  echo "⚠️ 发现 external/mcl 不完整，尝试手动 clone..."
  rm -rf external/mcl
  git clone https://github.com/herumi/mcl.git external/mcl
fi

echo "🎉 所有子模块准备就绪，可以编译项目了！"
echo "👉 现在你可以进入 build 目录并运行 cmake 和 make。"
