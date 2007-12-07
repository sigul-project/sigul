from setuptools import setup, find_packages
from turbogears.finddata import find_package_data

import os

packages=find_packages()
package_data = find_package_data(where='signserv',
    package='signserv')
if os.path.isdir('locales'):
    packages.append('locales')
    package_data.update(find_package_data(where='locales',
        exclude=('*.po',), only_in_packages=False))

setup(
    name="signserv",
    version=version,

    #description=description,
    #author=author,
    #author_email=email,
    #url=url,
    #download_url=download_url,
    #license=license,

    install_requires=[
        "TurboGears >= 1.0.3.2",
    ],
    scripts=["start-signserv.py"],
    zip_safe=False,
    packages=packages,
    package_data=package_data,
    keywords=['turbogears.app'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Framework :: TurboGears',
    ],
    test_suite='nose.collector',
)
