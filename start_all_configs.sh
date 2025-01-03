netdir="${1:-./}"
for d in $netdir/net_*/server_*.conf ; do
    wg-quick up $d
done
