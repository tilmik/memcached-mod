make
if [ $? -ne 0 ];then
	exit 1
fi
#ps -e | grep memcached | sed 's/^[ ]*//' | cut -f1 -d' ' | xargs kill -2
sudo make install
if [ $? -ne 0 ];then
	exit 1
fi
/usr/local/memcached/bin/memcached -vvv
