#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

First Time register project on pypi
https://pypi.org/manage/projects/


Update sphinx /docs
$ cd /docs
$ sphinx-build -b html source build/html
or
$ sphinx-apidoc -f -o source/ ../src/
$ make html

Best practices for setup.py and requirements.txt
https://caremad.io/posts/2013/07/setup-vs-requirement/
"""


from glob import glob
from os.path import basename
from os.path import splitext

from setuptools import find_packages
from setuptools import setup

setup(
    name='reg-pilot-api',
    version='0.0.2',  # also change in src/regps/__init__.py
    license='Apache Software License 2.0',
    description='RegPS: Regulation Portal Service API.',
    long_description="RegPS: A Regulation Portal Service to orchestate web app, vLEI validation, etc.",
    author='Lance Byrd',
    author_email='lance.byrd@rootsid.com',
    url='https://github.com/gleif-it/reg-pilot-api',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: Implementation :: CPython',
        # uncomment if you test on these interpreters:
        # 'Programming Language :: Python :: Implementation :: PyPy',
        # 'Programming Language :: Python :: Implementation :: IronPython',
        # 'Programming Language :: Python :: Implementation :: Jython',
        # 'Programming Language :: Python :: Implementation :: Stackless',
        'Topic :: Utilities',
    ],
    project_urls={
        'Issue Tracker': 'https://github.com/gleif-it/regulation-portal-service/issues',
    },
    keywords=[
        "secure attribution",
        "authentic data",
        "regulatory compliance",
        "vLEI",
        # eg: 'keyword1', 'keyword2', 'keyword3',
    ],
    python_requires='>=3.12.0',
    install_requires=[
        'apispec>=6.3.0',
        'asyncio>=3.4.3',
        'dataclasses_json>=0.5.7',
        'falcon>=3.1.0',
        'gunicorn>=20.1.0',
        'uvicorn>=0.30.3',
        'http_sfv>=0.9.8',
        'requests>=2.31.0',
        'swagger-ui-py>=22.7.13',
        'keri>=1.1.11',
        'fastapi>=0.111.1',
        'requests>=2.32.3',
        'python-multipart'
    ],
    extras_require={
        # eg:
        #   'rst': ['docutils>=0.11'],
        #   ':python_version=="2.6"': ['argparse'],
    },
    tests_require=[
        'coverage>=5.5',
        'pytest>=6.2.4',
    ],
    setup_requires=[
    ],
    entry_points={
        'console_scripts': [
            'regps = regps.app.cli.regps:main',
        ]
    },
)
