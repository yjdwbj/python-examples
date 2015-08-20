#client=pypy_epoll_clients.py
#client=pypy_threading_clients.py
client=stackless_gevent_clients.py
#client=gevent_clients.py
#mod="sockbasic.py"
#cmod="sockbasic.pypy-25.so"
cmod="sockbasic.so pg_driver.so cluster_mod.so"
#cmod="sockbasic.pypy-25.so"
#srv="pypy_eventlet_srv.py"
modsrc="sockbasic.pyx pg_driver.pyx cluster_mod.pyx"
modsetup="library_setup.py"
srv="stackless_gevent_srv.py"
proxy="stackless_gevent_proxy.py"
rexe="run_test.sh"
srvhost="root@srv:"
srvdir="/home/lcy/srv_dir"
clusterhost=~/cluster.txt
cluster_srv_dir="/opt/srv_dir"
#rsync $srv $modsrc $modsetup root@srv:/home/log/srv_dir
#rsync $client root@srv:/home/log/set_clients/

#rsync $srv  root@srv:srv_dir/
#cmod="sockbasic.so"
usage(){
    echo "Usage: `basename $0` -t target (etc. vclient,srv ,tclient,all)"
}

copy_to_tclient(){
hostfile=~/host.txt
parallel-ssh -i -h $hostfile mkdir -p /opt/client_test/{dev,app}_dir 
parallel-scp -h $hostfile $modsrc $modsetup make_lib.sh $client $rexe gen_random_uuids.py /opt/client_test/
#parallel-ssh -i -h $hostfile rm /opt/client_test/{dev,app}_dir/*.{log,log.*}
#parallel-ssh -i -h $vhostfile rm /opt/client_test/{dev,app}_dir/*.{log,log.*}
parallel-ssh -i -h $hostfile /opt/client_test/make_lib.sh
}

copy_to_vclient(){
vhostfile=~/vhost.txt
parallel-ssh -i -h $vhostfile mkdir -p /opt/client_test/{dev,app}_dir
parallel-scp -h $vhostfile $modsrc $modsetup make_lib.sh $client $rexe gen_random_uuids.py /opt/client_test/
parallel-ssh -i -h $vhostfile /opt/client_test/make_lib.sh

}

copy_to_srv(){
    echo "copy files to srv"
srvfile="$modsrc $proxy run_node.sh $modsetup"
rsync  $srvfile  $srvhost$srvdir
parallel-ssh -i -H root@srv " cd /home/lcy/srv_dir ; LD_LIBRARY_PATH=/opt/stackless-279/lib /opt/stackless-279/bin/python $modsetup build_ext && chown lcy:lcy -R *"
}

copyt_to_cluster(){
srvfile="$modsrc $srv run_node.sh $modsetup"
parallel-ssh -i -h $srvhost "mkdir -pv $cluster_srv_dir"
parallel-scp -h $srvhost $srvfile  $cluster_srv_dir
parallel-ssh -i -h $srvhost /opt/stackless-279/bin/python $modsetup build_ext --inplace

}


run_target()
{
    case $1 in
        'vclient')
            copy_to_vclient
            ;;
        'tclient')
            copy_to_tclient
            ;;

        'srv')
            copy_to_srv
            ;;
        'all')
            copy_to_srv
            copy_to_vclient
            copy_to_tclient
            ;;
       \?)
           usage
           ;;
   esac
}

TARGET=
[ $# -eq 0 ] && usage
while getopts :t: OPTION
do
    case $OPTION in
        t)
            run_target $OPTARG
            ;;
        \?)
            usage
            ;;
    esac
done

