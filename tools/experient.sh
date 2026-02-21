#!/bin/bash
trap 'echo "Caught Ctrl+C, killing all frontend.exe..."; pkill frontend.exe ; exit 1' INT

# ==================== 参数设置 ====================
# number_of_parties=(5 10 15 20)    # 参与方数量
# set_sizes=(6 10 14)         # set size 指数（代表 2^10, 2^14, 2^18, 2^20）

number_of_parties=(30)    # 参与方数量
set_sizes=(12 4)         # set size 指数（代表 2^10, 2^14, 2^18, 2^20）
# ==================================================

# 外层循环：不同 n
for n in "${number_of_parties[@]}"; do

    # 设置对应的 t 值
    case $n in
        5)  t=3 ;;
        10) t=5 ;;
        15) t=8 ;;
        20) t=10 ;;
        *)  t=$((n/2)) ;;   # 默认情况，防止将来增加其他 n
    esac

    # 中层循环：不同 set size
    for m_exp in "${set_sizes[@]}"; do
        date
        echo "=============================="
        echo "Running for n=$n, t=$t, m=2^${m_exp}"
        echo "=============================="

        m=$m_exp   # 若你的程序需要实际集合大小，请改成 m=$((1 << m_exp))

        # 生成临时脚本
        script_file=./tools/"benchmark.sh"
        echo "#!/bin/bash" > "$script_file"
        echo "# Auto-generated script for n = $n, m = $m, t = $t" >> "$script_file"
        echo "" >> "$script_file"

        # 为每个参与方生成执行命令
        for ((p=0; p<$n; p++)); do
            echo "./bin/frontend.exe -n $n -t $t -m $m -p $p -M &" >> "$script_file"
            # echo "./bin/frontend.exe -n $n -t $t -m $m -p $p &" >> "$script_file"
        done

        chmod +x "$script_file"

        # 确保上一次的 frontend.exe 已结束
        while pgrep frontend.exe >/dev/null; do
            echo "Previous instances of frontend.exe are still running. Waiting..."
            sleep 5
        done

        echo "Previous instances have been terminated. Starting new instances..."
        sh "$script_file"

        # # 等待一段时间再进入下一轮
        # sleep_time=5s
        # sleep $sleep_time
        while pgrep frontend.exe >/dev/null; do
            sleep 5
        done
        echo "Completed for n=$n, t=$t, m=2^${m_exp}"
        echo
    done
done
