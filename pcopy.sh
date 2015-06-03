#client=pypy_epoll_clients.py
#client=pypy_threading_clients.py
client=stackless_gevent_clients.py
#client=gevent_clients.py
#mod="sockbasic.py"
#cmod="sockbasic.pypy-25.so"
cmod="sockbasic.so pg_driver.so cluster.so"
#cmod="sockbasic.pypy-25.so"
#srv="pypy_eventlet_srv.py"
modsrc="sockbasic.pyx pg_driver.pyx stackless_cluster_srv.pyx"
modsetup="library_setup.py"
srv="stackless_gevent_srv.py"
rexe="run_test.sh"
rsync $srv $modsrc $modsetup root@srv:/home/log/srv_dir
rsync $client root@srv:/home/log/set_clients/

#rsync $srv  root@srv:srv_dir/
#cmod="sockbasic.so"
hostfile=~/host.txt
vhostfile=~/vhost.txt
parallel-ssh -i -h $hostfile mkdir -p /opt/client_test/{dev,app}_dir 
parallel-ssh -i -h $vhostfile mkdir -p /opt/client_test/{dev,app}_dir
parallel-scp -h $hostfile $modsrc $modsetup make_lib.sh $client $rexe gen_random_uuids.py /opt/client_test/
parallel-scp -h $vhostfile $modsrc $modsetup make_lib.sh $client $rexe gen_random_uuids.py /opt/client_test/
#parallel-ssh -i -h $hostfile rm /opt/client_test/{dev,app}_dir/*.{log,log.*}
#parallel-ssh -i -h $vhostfile rm /opt/client_test/{dev,app}_dir/*.{log,log.*}
parallel-ssh -i -h $hostfile /opt/client_test/make_lib.sh
parallel-ssh -i -h $vhostfile /opt/client_test/make_lib.sh

