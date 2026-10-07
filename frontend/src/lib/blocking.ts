/** Generate firewall commands to block an attacker IP. The dashboard only *shows*
 *  the commands — nothing privileged runs — so you stay in control of your own network. */

/** True for addresses on your own machine/LAN, where a block could cut you off. */
export function isLocalIp(ip: string): boolean {
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return (
      a === 10 ||                       // 10.0.0.0/8
      a === 127 ||                      // loopback
      (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
      (a === 192 && b === 168) ||       // 192.168.0.0/16
      (a === 169 && b === 254)          // link-local
    );
  }
  const l = ip.toLowerCase();
  return l === "::1" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd"); // IPv6 loopback/link-local/ULA
}

export type BlockPlan = {
  ip: string;
  local: boolean;
  iptables: { block: string; unblock: string };
  nftables: { block: string; unblock: string };
};

export function blockPlan(ip: string): BlockPlan {
  return {
    ip,
    local: isLocalIp(ip),
    iptables: {
      block: `sudo iptables -I INPUT -s ${ip} -j DROP`,
      unblock: `sudo iptables -D INPUT -s ${ip} -j DROP`,
    },
    nftables: {
      block: `sudo nft add rule inet filter input ip saddr ${ip} drop`,
      unblock: `sudo nft -a list chain inet filter input   # find the handle, then:\n# sudo nft delete rule inet filter input handle <N>`,
    },
  };
}
