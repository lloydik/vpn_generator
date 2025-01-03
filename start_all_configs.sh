for d in net_*/server_*.conf ; do
    wg-quick up $d
done
