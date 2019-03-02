#!/usr/bin/env python
import setuptools


install_requirements = [
    'prompt_toolkit',
    'requests==2.21.0',
]


def main():
    setuptools.setup(
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
