#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('CHANGELOG.rst') as changelog_file:
    changelog = changelog_file.read()

requirements = [
    # TODO: put package requirements here
]

setup_requirements = [
    'pytest-runner',
    # TODO(glasserc): put setup requirements (distutils extensions, etc.) here
]

test_requirements = [
    'pytest',
    # TODO: put package test requirements here
]

setup(
    name='sign-xpi-lib',
    version='0.1.0',
    description="A library to handle the manipulations of signing XPIs at Mozilla.",
    long_description=readme + '\n\n' + changelog,
    author="Ethan Glasser-Camp",
    author_email='eglassercamp@mozilla.com',
    url='https://github.com/mozilla-services/sign-xpi-lib',
    packages=find_packages(include=['sign_xpi_lib']),
    include_package_data=True,
    install_requires=requirements,
    license="MPL",
    zip_safe=False,
    keywords='sign_xpi',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    setup_requires=setup_requirements,
)
