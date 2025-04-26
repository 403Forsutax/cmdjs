// terminal.js

const { spawn, exec } = require('child_process');
const readline = require('readline');
const fs = require('fs');
const path = require('path');

let currentDir = process.cwd(); // Folder aktif sekarang

const rl = readline.createInterface({
    input: process.stdin,
        output: process.stdout
        });

        function welcome() {
            console.clear();
                console.log('=== Terminal.js CommonJS ===');
                    console.log('Direktori saat ini:', currentDir);
                        console.log('Ketik "help" untuk bantuan.\n');
                        }

                        function updatePrompt() {
                            rl.setPrompt(`[${currentDir}] > `);
                                rl.prompt();
                                }

                                function handleInput(line) {
                                    const input = line.trim();

                                        if (input === 'exit') {
                                                console.log('Sampai jumpa!');
                                                        process.exit(0);
                                                            }

                                                                if (input === 'help') {
                                                                        console.log('\nPerintah tersedia:');
                                                                                console.log('- help        : tampilkan bantuan');
                                                                                        console.log('- exit        : keluar terminal');
                                                                                                console.log('- cd <path>   : berpindah direktori');
                                                                                                        console.log('- spawnbash   : bypass ke bash normal');
                                                                                                                console.log('- [perintah]  : eksekusi command linux biasa\n');
                                                                                                                        updatePrompt();
                                                                                                                                return;
                                                                                                                                    }

                                                                                                                                        if (input.startsWith('cd ')) {
                                                                                                                                                const target = input.slice(3).trim();
                                                                                                                                                        const resolved = path.resolve(currentDir, target);
                                                                                                                                                                if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
                                                                                                                                                                            currentDir = resolved;
                                                                                                                                                                                        console.log(`Pindah ke: ${currentDir}`);
                                                                                                                                                                                                } else {
                                                                                                                                                                                                            console.error('Direktori tidak ditemukan.');
                                                                                                                                                                                                                    }
                                                                                                                                                                                                                            updatePrompt();
                                                                                                                                                                                                                                    return;
                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                            if (input === 'spawnbash') {
                                                                                                                                                                                                                                                    console.log('Mencoba masuk ke /bin/bash...');
                                                                                                                                                                                                                                                            const bash = spawn('/bin/bash', {
                                                                                                                                                                                                                                                                        stdio: 'inherit',
                                                                                                                                                                                                                                                                                    cwd: currentDir
                                                                                                                                                                                                                                                                                            });

                                                                                                                                                                                                                                                                                                    bash.on('exit', () => {
                                                                                                                                                                                                                                                                                                                console.log('\nKembali ke Terminal.js');
                                                                                                                                                                                                                                                                                                                            updatePrompt();
                                                                                                                                                                                                                                                                                                                                    });
                                                                                                                                                                                                                                                                                                                                            return;
                                                                                                                                                                                                                                                                                                                                                }

                                                                                                                                                                                                                                                                                                                                                    // Eksekusi command biasa
                                                                                                                                                                                                                                                                                                                                                        exec(input, { cwd: currentDir }, (err, stdout, stderr) => {
                                                                                                                                                                                                                                                                                                                                                                if (err) console.error(`Error: ${err.message}`);
                                                                                                                                                                                                                                                                                                                                                                        if (stderr) console.error(stderr);
                                                                                                                                                                                                                                                                                                                                                                                if (stdout) console.log(stdout);
                                                                                                                                                                                                                                                                                                                                                                                        updatePrompt();
                                                                                                                                                                                                                                                                                                                                                                                            });
                                                                                                                                                                                                                                                                                                                                                                                            }

                                                                                                                                                                                                                                                                                                                                                                                            // Start
                                                                                                                                                                                                                                                                                                                                                                                            welcome();
                                                                                                                                                                                                                                                                                                                                                                                            updatePrompt();
                                                                                                                                                                                                                                                                                                                                                                                            rl.on('line', handleInput);