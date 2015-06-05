ulimit -Hn 1048576
ulimit -Sn 1048576
pyexe="/opt/stackless-279/bin/python"
exefile=stackless_gevent_srv.py
build_mod=library_setup.py
#exefile=gevent_clients.py

start_run(){
cd /opt/srv_dir
#./gevent_app_demon.py -H $srv -f $num.bin -u $num -b 1 &
#./stackless_app_demon.py -H $srv -f $num.bin -u $num -b 1 &
rm *.log *.log.*
$pyexe $build_mod build_ext --inplace
$pyexe  $exefile -I eth1 -B eth0
}
start_run 
exit 0

