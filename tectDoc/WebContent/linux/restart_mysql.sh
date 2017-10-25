#!/bin/bash
pgrep mysqld &> /dev/null
if [ $? -gt 0 ]
then
echo "`date` mysql is stop" >> /etc/listener/restart_mysql.log
service mysql start
else
echo "`date` mysql running" >> /etc/listener/restart_mysql.log
fi
