export interface Connection {
    id: number;
    timestamp: string;
    srcIP: string;
    srcPort: number;
    dstIP: string;
    dstPort: number;
    protocol: string;
    isInbound: boolean;
    raw: string;
}

const HONEYPOT_IP = "159.223.6.94";

export const parseData = (text: string): Connection[] => {
    const lines = text.split('\n');
    const connections: Connection[] = [];
    let id = 0;

    // Regex for standard tcpdump line: 
    // 16:37:44.809861 IP 1.2.3.4.1234 > 5.6.7.8.80: tcp 0
    const regex = /^(\d{2}:\d{2}:\d{2}\.\d{6}) IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+) > (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+): (.*)/;

    for (const line of lines) {
        const match = line.match(regex);
        if (match) {
            const dstIP = match[4];
            connections.push({
                id: ++id,
                timestamp: match[1],
                srcIP: match[2],
                srcPort: parseInt(match[3]),
                dstIP: dstIP,
                dstPort: parseInt(match[5]),
                protocol: match[6],
                isInbound: dstIP === HONEYPOT_IP,
                raw: line
            });
        }
    }
    return connections;
};
