try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Extract, defang and resolve host names and IPs',
    'author': 'Frank Denis',
    'url': 'https://github.com/jedisct1/ipgrep',
    'download_url': 'https://github.com/jedisct1/ipgrep',
    'author_email': 'github@pureftpd.org',
    'version': '0.2',
    'install_requires': [
      'pycares', 'urllib3'
    ],
    'packages': ['ipgrep'],
    'scripts': [],
    'name': 'ipgrep'
}

setup(**config)
