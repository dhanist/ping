I always forget to type ``ping6`` to ping ipv6 address so I wrote this piece of code.

**What it does?**  
When supplied with host, it will try to use ipv6 address and when ipv6 unavailable then fallback to ipv4.  
It will adjust IP version based on the argument supplied.

This ping is different from the original Linux ping. It will send icmp packet soon after icmp reply received or timeout limit reached, just like Cisco IOS. Also, the output is similar to Cisco IOS, you can even do something like ``ping google.com repeat 100``

<br />

**Compile with**

    gcc -o ping ping.c

Only root can create raw socket, so you need to change ownership to root and set suid flag.  
Do this with root user

    chown root:root ping
    chmod 4755 ping

<br />
**Usage**

    ping google.com

    # or
    ping 8.8.8.8

    # For ipv6 only use 
    ping ipv6 google.com

    # or for ipv4 only
    ping ipv6 google.com

    # run ping without arguments to print usage
