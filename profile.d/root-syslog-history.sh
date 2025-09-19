if [ $UID == 0 ]; then
	   echo '*** Logged in as root. Commands are logged ***'
	      shopt -s syslog_history 
fi

