python3 manage.py migrate --settings=base.settings
# uwsgi --env DJANGO_SETTINGS_MODULE=runthe_backend.settings.prod --ini runthe_backend.local.ini
uvicorn base.asgi:application --port 8000 --host 0.0.0.0 --workers $(($(awk '/^processor/{n+=1}END{print n}' /proc/cpuinfo)*2+1)) --lifespan off