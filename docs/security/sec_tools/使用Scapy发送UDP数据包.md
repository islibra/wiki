# 使用Scapy发送UDP数据包

!!! quote "官方网址: <https://scapy.net/>"

## 使用步骤

1. 下载地址: <https://github.com/secdev/scapy/releases>
1. 解压: `tar -zxvf scapy-2.4.3.tar.gz`
1. 运行

    ```bash
    $ ./run_scapy
    INFO: Can't import matplotlib. Won't be able to plot.
    INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().
    WARNING: No route found for IPv6 destination :: (no default route?)
    INFO: Can't import python-cryptography v1.7+. Disabled WEP decryption/encryption. (Dot11)
    INFO: Can't import python-cryptography v1.7+. Disabled IPsec encryption/authentication.
    WARNING: IPython not available. Using standard Python shell instead.
    AutoCompletion, History are disabled.

                         aSPY//YASa
                 apyyyyCY//////////YCa       |
                sY//////YSpcs  scpCY//Pp     | Welcome to Scapy
     ayp ayyyyyyySCP//Pp           syY//C    | Version git-archive.dev3047580162
     AYAsAYYYYYYYY///Ps              cY//S   |
             pCCCCY//p          cSSps y//Y   | https://github.com/secdev/scapy
             SPPPP///a          pP///AC//Y   |
                  A//A            cyP////C   | Have fun!
                  p///Ac            sC///a   |
                  P////YCpc           A//A   | Craft packets like it is your last
           scccccp///pSP///p          p//Y   | day on earth.
          sY/////////y  caa           S//P   |                      -- Lao-Tze
           cayCyayP//Ya              pY/Ya   |
            sY/PsY////YCc          aC//Yp
             sc  sccaCY//PCypaapyCP//YSs
                      spCPY//////YPSps
                           ccaacs

    >>>
    ```

1. 发送数据包

    ```bash
    >>> data = "Hello Scapy"
    >>> pkt = IP(src='x.x.x.x', dst='x.x.x.x')/UDP(sport=12345, dport=53)/data
    >>> send(pkt, inter=1, count=1)
    .
    Sent 1 packets.
    ```
