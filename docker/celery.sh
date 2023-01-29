# celery multi stopwait 2 -A runthe_backend --pidfile=/var/run/auth%n.pid --logfile=/var/run/auth%n.log --loglevel=INFO
celery multi start 2 -A base --logfile=/usr/src/app/logs/$1_%n.log --loglevel=INFO
# celery multi start 2 -A runthe_backend --logfile=/var/run/auth%n.log --loglevel=INFO 
celery -A base worker --beat --scheduler django --loglevel=info --logfile=/usr/src/app/logs/$1_celerybeat.log -E -n master@node
# rm -rf /var/run/auth_celerybeat.pid