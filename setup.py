#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
import os

from setuptools import setup, find_packages

setup(
    name = 'PyChef',
    version = '0.3.0',
    packages = find_packages(),
    author = 'Noah Kantrowitz',
    author_email = 'noah@coderanger.net',
    description = 'Python implementation of a Chef API client.',
    long_description = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read(),
    license = 'Apache 2.0',
    keywords = '',
    url = 'http://github.com/coderanger/pychef',
    classifiers = [
        #'Development Status :: 1 - Planning',
        #'Development Status :: 2 - Pre-Alpha',
        #'Development Status :: 3 - Alpha',
        #'Development Status :: 4 - Beta',
        'Development Status :: 5 - Production/Stable',
        #'Development Status :: 6 - Mature',
        #'Development Status :: 7 - Inactive',
        'License :: OSI Approved :: Apache License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    zip_safe = False,
    install_requires = ['six>=1.9.0','requests>=2.7.0','pycryptodome>=3.6.0'],
    tests_require = ['unittest2', 'mock'],
    test_suite = 'unittest2.collector',
)
