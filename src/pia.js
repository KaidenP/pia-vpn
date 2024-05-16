#!/usr/bin/env node

import child_process from 'node:child_process'
import {promisify} from  'node:util'
const exec = promisify(child_process.exec)
import fs from 'node:fs/promises'
import got from 'got'
import FormData from "form-data"
import Docker from "dockerode"
import os from 'os'
const oldlog = console.log.bind(console)
console.log = function (...args) {
    oldlog('[' + (new Date()).toLocaleTimeString() + ']: ', ...args)
}

const docker = new Docker({socketPath: '/var/run/docker.sock'})
let qbt

if (!process.env.PIA_USERNAME || process.env.PIA_USERNAME === '') throw new Error("Missing PIA_USERNAME environment variable")
if (!process.env.PIA_PASSWORD || process.env.PIA_PASSWORD === '') throw new Error("Missing PIA_PASSWORD environment variable")
if (!process.env.DATA_DIR || process.env.DATA_DIR === '') throw new Error("Missing DATA_DIR environment variable")

const loginData = new FormData()
loginData.append('username', process.env.PIA_USERNAME)
loginData.append('password', process.env.PIA_PASSWORD)

const {token} = await got.post('https://www.privateinternetaccess.com/api/client/v2/token', {
    body: loginData
}).json();

console.log(`Got token : ${token.substring(0,5)}*****`);

async function cleanup() {
    console.log("Cleaning up...")
    if (qbt) {
        console.log("Removing qbt container...")
        try { await qbt.remove({force:true}) } catch (e) { console.log('Removing qbt failed: ' + e.reason) }
    }
    console.log("Cleaning up... Done!")
}

const trap = ['exit', 'SIGINT', 'SIGTERM']
function exitHandler(signal="unknown") {
    process.stdin.resume()

    process.stdout.write((new Date()).toString() + ': ')
    console.log(`Exiting due to "${signal}"`)

    trap.forEach(sig=>{
        process.removeListener(sig, exitHandler)
    })
    cleanup().then(()=>process.exit())
}

trap.forEach(sig=>{
    process.once(sig, exitHandler)
})
process.once('uncaughtException', async function (err) {
    console.error(err.stack)
    exitHandler()
})

async function startQbt(port) {
    let containers = await docker.listContainers()
    for (let i=0; i<containers.length; i++) {
        for (let j=0; j<containers[i].Names.length; j++) {
            let name = containers[i].Names[j]
            let match = /^\/qbt-([a-z0-9]+)/.exec(name)
            if (match) {
                let ct = docker.getContainer(match[1])
                try {
                    await ct.inspect()
                } catch (e) {
                    if (e.reason === 'no such container') {
                        console.log(`Warning: Deleting orphan qbt container: qbt-${match[1]}`)
                        await docker.getContainer('qbt-' + match[1]).remove({force:true})
                    }
                }
            }
        }
    }
    process.stdout.write('Pulling qbittorent docker image')
    await docker.pull('qbittorrentofficial/qbittorrent-nox:latest', function(err, stream) {
        //...
        docker.modem.followProgress(stream, onFinished, onProgress);

        async function onFinished() {
            console.log(' Done!')
            console.log("Starting qbt...")
            try {
                await docker.getContainer(`qbt-${os.hostname()}`).remove({force:true})
            } catch (e) {
                // Fail silently
            }
            qbt = await docker.createContainer( {
                Image: 'qbittorrentofficial/qbittorrent-nox:latest',
                AttachStdout: true,
                AttachStderr: true,
                Labels: {
                    'homepage.group': 'Media',
                    'homepage.name': 'qBittorrent',
                    'homepage.href': 'https://home.kaidenprince.com/app/qBittorent',
                    'homepage.widget.type': 'qbittorent',
                    'homepage.widget.url': `http://qbt-${os.hostname()}:8080`
                },
                HostConfig: {
                    NetworkMode: `container:${os.hostname()}`,
                    AutoRemove: true,
                    Binds: [
                        `${process.env.DATA_DIR}:/data`,
                        `${process.env.DATA_DIR}/.config:/config`,
                    ]
                },
                name: `qbt-${os.hostname()}`,
                Env: [
                    "PUID=10000",
                    "PGID=10000",
                    'UMASK=002',
                    'QBT_LEGAL_NOTICE=confirm'
                ],
                Cmd: [`--torrenting-port=${port}`]
            })
            await qbt.start()
            qbt.attach({stream: true, stdout: true, stderr: true}, function (err, stream) {
                stream.pipe(process.stdout);
            })
            console.log("Starting qbt... DONE!")
        }
        function onProgress() {
            process.stdout.write(".");
        }
    })
}

async function connect(ip, hostname, DIP=false) {
    console.log('Generating Keys...')
    const privkey = (await exec(`wg genkey`)).stdout
    const pubkey = (await exec(`echo '${privkey}' | wg pubkey`)).stdout

    console.log(`Registering keys with PIA API...`)
    let pia_json
    if (DIP) {
        pia_json = await got.get(`https://${ip}:1337/addKey?${(new URLSearchParams({
            pubkey: pubkey
        })).toString()}`, {
            headers: {
                Host: hostname
            },
            https: {
                certificateAuthority: await fs.readFile('ca.rsa.4096.crt')
            },
            username: `dedicated_ip_${DIP.dip_token}`,
            password: ip
        }).json()
    } else {
        pia_json = await got.get(`https://${ip}:1337/addKey?${(new URLSearchParams({
            pubkey: pubkey,
            pt: token
        })).toString()}`, {
            headers: {
                Host: hostname
            },
            https: {
                certificateAuthority: await fs.readFile('ca.rsa.4096.crt')
            }
        }).json()
    }
    if (pia_json.status !== 'OK') throw new Error("Server did not return OK. Stopping now.")

    console.log(`Connecting to ${hostname}...`)

    console.log('Setting up Firewall...')
    await exec('wg-quick down pia || true')
    await exec('ip6tables -P INPUT DROP && ip6tables -P OUTPUT DROP && ip6tables -P FORWARD DROP || echo "Setting ip6tables failed"')
    await exec('iptables -P INPUT DROP && iptables -P OUTPUT DROP && iptables -P FORWARD DROP')
    await exec('iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
    await exec('iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
    await exec('iptables -A OUTPUT -o lo -j ACCEPT && iptables -A INPUT -i lo -j ACCEPT')
    await exec('iptables -A OUTPUT -o pia -j ACCEPT')
    await exec(`iptables -A OUTPUT -p udp --dport ${pia_json.server_port} -d ${ip} -o eth0 -j ACCEPT`)
    await exec(`iptables -A INPUT -p tcp -i eth0 --dport 8080 -j ACCEPT`)
    console.log('Setting up Firewall... Done!')

    await fs.writeFile('/etc/wireguard/pia.conf', `[Interface]
Address = ${pia_json.peer_ip}
PrivateKey = ${privkey}
DNS = ${pia_json.dns_servers[0]}
PostUp = ip rule add from $(ip a show dev eth0 | grep 'inet ' | awk '{ print $2; }' | sed -r 's@/[0-9]+$@@') table main
PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED,RELATED -j REJECT
PreDown = ip rule del from $(ip a show dev eth0 | grep 'inet ' | awk '{ print $2; }' | sed -r 's@/[0-9]+$@@') table main
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -m conntrack ! --ctstate ESTABLISHED,RELATED -j REJECT
[Peer]
PersistentKeepalive = 25
PublicKey = ${pia_json.server_key}
AllowedIPs = 0.0.0.0/0
Endpoint = ${ip}:${pia_json.server_port}
`)
    console.log(`Starting VPN...`)
    console.log(`${(await exec('wg-quick up pia')).stderr}`)
    console.log(`Done!`)


    console.log(`Setup Port Forwarding @${ip}...`)
    let pf_json = await got.get(`https://${ip}:19999/getSignature?${(new URLSearchParams({
        token: token
    })).toString()}`, {
        headers: {
            Host: hostname
        },
        https: {
            certificateAuthority: await fs.readFile('ca.rsa.4096.crt')
        }
    }).json()
    if (pf_json.status !== 'OK') throw new Error('Error Registering Port')
    let payload = JSON.parse(atob(pf_json.payload))
    console.log(`We got port ${payload.port}`)
    await exec(`iptables -A INPUT -p udp -i pia --dport ${payload.port} -j ACCEPT`)
    await exec(`iptables -A INPUT -p tcp -i pia --dport ${payload.port} -j ACCEPT`)

    async function portForward() {
        let pf_res = await got.get(`https://${ip}:19999/bindPort?${(new URLSearchParams({
            signature: pf_json.signature,
            payload: pf_json.payload
        })).toString()}`, {
            headers: {
                Host: hostname
            },
            https: {
                certificateAuthority: await fs.readFile('ca.rsa.4096.crt')
            }
        }).json()

        if (pf_res.status !== 'OK') throw new Error('Port Refresh Failed')

        console.log("Doing a ping test")
        try {
            await exec('ping -c 5 8.8.8.8')
        } catch (e) {
            throw new Error('Ping test failed')
        }
        console.log("Done!")
    }

    setInterval(portForward, 15*60*1000)
    await portForward()
    await startQbt(payload.port)
}

let DIP
if (!process.env.PIA_DIP || process.env.PIA_DIP === '') {
    console.log("Not using DIP.")
    DIP=false
} else {
    DIP = (await got.post('https://www.privateinternetaccess.com/api/client/v2/dedicated_ip',{
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Token ${token}`
        },
        body: JSON.stringify({ tokens: [process.env.PIA_DIP] })
    }).json())[0]

    if (DIP.status !== 'active') throw new Error(`Got bad response: ${JSON.stringify(DIP)}`)
    await connect(DIP.ip, DIP.cn, DIP)
}
