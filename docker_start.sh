#!/bin/bash


start_onehost()
{
    echo "start_onehost \$1 $1 \$2 $2"
# $1 is number, 
n=`echo $1 | cut -b 2`
uuid=`docker run --net=none -idt -m 3000m --cpuset-cpus=$n  $2   `
pid=`docker inspect -f '{{.State.Pid}}' $uuid`
docker exec $uuid /etc/init.d/ssh start
ln -s /proc/$pid/ns/net /var/run/netns/$pid
pairA=${pid}A
pairB=${pid}B
ip link add $pairA type veth peer name $pairB
brctl addif $bgname $pairA
ip link set $pairA up
ip link set $pairB netns $pid
ip netns exec $pid ip link set dev $pairB name eth0
ip netns exec $pid ip link set eth0 up
ip netns exec $pid ip addr add 172.17.42.$1/16 dev eth0
ip netns exec $pid ip route add default via $bgw
}

usage()
{
    echo "args number $#"
    echo "arg list $@"
    echo "$1 number"
}

loopstart()
{

    echo "loopstart \$1 $1 \$2 $2"
    for n in `seq 10 1$2`;
    do start_onehost $n $1
    done
}


bgname="docker0"
bgw=`ip addr show docker0 | grep "inet" | awk '{print $2}' | awk -F "/" '{print $1}'`
mkdir -p /var/run/netns
if [ "$#" -lt 2 ]; then
    usage $0
else
    loopstart $1 $2  #$1 == repo name , $2 ==  number of start hosts
fi
