from setuptools import setup, find_packages
from turbogears.finddata import find_package_data

import os

packages=find_packages()
package_data = find_package_data(where='sigul',
    package='sigul')
if os.path.isdir('locales'):
    packages.append('locales')
    package_data.update(find_package_data(where='locales',
        exclude=('*.po',), only_in_packages=False))

setup(
    name="sigul",
    version="0.0.1",
    description="An automated gpg signing system",
    url="https://fedorahosted.org/sigul",
    license="GPL",

    install_requires=[
        "TurboGears >= 1.0.3.2",
    ],
    scripts=["start-sigul.py"],
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
