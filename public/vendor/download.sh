#!/bin/bash
# CDN资源本地化下载脚本
# 在 public/vendor/ 目录下执行: bash download.sh

echo "正在下载 Chart.js..."
curl -sL -o chart.min.js "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
echo "Chart.js 下载完成: $(wc -c < chart.min.js) bytes"

echo "正在下载 html2canvas..."
curl -sL -o html2canvas.min.js "https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js"
echo "html2canvas 下载完成: $(wc -c < html2canvas.min.js) bytes"

echo ""
echo "下载完成！文件列表："
ls -lh *.js 2>/dev/null || echo "没有找到JS文件"
