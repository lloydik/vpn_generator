for d in net_*/server_*.conf ; do
    wg-quick down $d
done
