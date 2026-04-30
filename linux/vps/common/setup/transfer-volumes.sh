#!/bin/bash

# Transfer website_data volume
tar -czvf - -C ~/ website_data | ssh root@172.232.234.222 "tar -xzvf - -C /"

# Transfer mysql_data volume
tar -czvf - -C ~/ mysql_data | ssh root@172.232.234.222 "tar -xzvf - -C /"

# Transfer vhost volume
tar -czvf - -C ~/ vhost | ssh root@172.232.234.222 "tar -xzvf - -C /"


# 172.232.234.222