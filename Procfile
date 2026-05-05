release: python manage.py migrate --noinput && python manage.py collectstatic --noinput
web: gunicorn emailsmanager.wsgi --log-file - --bind 0.0.0.0:$PORT
