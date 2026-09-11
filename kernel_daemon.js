const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');

const WORKDIR = process.cwd();
const SOCKET_PATH = path.join(WORKDIR, 'kernel.sock');

if (fs.existsSync(SOCKET_PATH)) {
    fs.unlinkSync(SOCKET_PATH);
}

const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
        if (req.method === 'POST' && req.url === '/execute') {
            try {
                const { command, args = [] } = JSON.parse(body);
                const child = spawn(command, args, { shell: true, cwd: WORKDIR });
                
                let stdout = '';
                let stderr = '';

                child.stdout.on('data', data => { stdout += data; });
                child.stderr.on('data', data => { stderr += data; });

                child.on('close', code => {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ code, stdout, stderr }));
                });
            } catch (err) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        } else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Endpoint not found' }));
        }
    });
});

server.listen(SOCKET_PATH, () => {
    fs.chmodSync(SOCKET_PATH, '600');
    console.log(`[+] Kernel execution daemon bound to Unix socket: ${SOCKET_PATH}`);
});
