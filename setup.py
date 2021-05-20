# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

from setuptools import setup, find_packages
with open("requirements.txt", "r") as file:
    reqs = [req for req in file.read().splitlines() if (len(req) > 0 and not req.startswith("#"))]
__author__ = 'Jose Valente <jose.valente@nokia.com>'

setup(
    name="napalm-srl",
    version="0.2.0",
    packages=find_packages(),
    author="Jose Valente",
    author_email="jose.valente@nokia.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/tbd",
    include_package_data=True,
    install_requires=reqs,
)
