cdir=/opt/client_test
client=stackless_gevent_clients.py
cd $cdir
/opt/stackless-279/bin/python library_setup.py build_ext --inplace
cp *.so $client app_dir/
cp *.so $client dev_dir/
