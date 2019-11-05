#!/usr/bin/env python
import sys

import setuptools

if sys.version_info < (3, 6):
    sys.exit('Python < 3.6 is not supported')

install_requirements = [
    'python-dateutil',
    'prompt_toolkit>=2',
    'requests',
]


def main():
    setuptools.setup(
        python_requires='>=3.6',
        entry_points={
            'console_scripts': [
                'mreg-cli = mreg_cli.main:main',
            ],
        },
        install_requires=install_requirements,
        packages=setuptools.find_packages(
            '.', include=('mreg_cli', 'mreg_cli.*')),
    )


if __name__ == '__main__':
    main()
