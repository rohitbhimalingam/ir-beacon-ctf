# IR Beacon CTF Write-up

Flag: `0x1337{pl5_g3t_4_5y54dm1n}`

## Peeling the script

The attached PowerShell artifact is Base64-encoded gzip. Decompressing it reveals a downloader that XORs each endpoint byte with `0x5A`, producing `/beacon`. It derives an `X-Auth` value as the lowercase hexadecimal HMAC-SHA256 of the current UTC date in `yyyyMMdd` format, using the embedded challenge secret, then requests the ZIP from the target host.

## Recovering the staged data

The three challenge services returned the staged ZIP when requested at `/beacon` with the computed header. The ZIP contained a packet capture, a PNG, and a router configuration:

- DNS query names in `beacon_capture.pcap` carry hex-encoded bytes in their first labels. Reassembling them in packet order yields `0x1337{pl5_g`.
- Reading the RGB least-significant bits of `cam_backup.png` yields `3t_4_5y54`.
- Decoding the Cisco type-7 password `121D08461C16` in `rtr-config.txt` yields `dm1n}`.

Concatenating the three parts gives the flag above.
