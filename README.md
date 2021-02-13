## PEP4Django

Generic PEP middleware for Django Framework


## Installation

```
pip install -U -r requirements.txt
```


### Configuration

- in Demo/settings.py

```
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'Demo.middleware.django_pep.DjangoPEPMiddleware',               # DjangoPEP here (last)
]
```

```
# DjangoPEP Middleware settings
DJANGOPEP_PRODUCT = 1  # 1-WSO2 IS, 2-AuthZForce
DJANGOPEP_URL = 'https://localhost:9443/api/identity/entitlement/decision/pdp'
DJANGOPEP_USER = 'admin'
DJANGOPEP_PASSWORD = 'admin'
DJANGOPEP_TOKEN = ''
DJANGOPEP_DEBUG = True
DJANGOPEP_IGNORE = ['/$', '/admin/*', '/accounts/*']
```

- In WSO2 IS create new XACML policy from sample (Extra/NewTicket.xml)


### Run DjangoPEP

```
python manage.py runserver
```


## Contributors

Welkson Renny de Medeiros - <welkson.medeiros@ifrn.edu.br>

Carlos Eduardo da Silva - <contact@kaduardo.me>


## License

The MIT License (MIT)
