#from setuptools import setup, find_packages
from setuptools import *

description='An implementation of the Acquia HTTP HMAC Spec (https://github.com/acquia/http-hmac-spec) in Python.'

setup(
    name='http-hmac-python',
    version='2.4.0',
    description=description,
    long_description=description,
    url='https://github.com/baliame/http-hmac-python',
    author='Baliame',
    author_email='akos.toth@cheppers.com',
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='hmac development library',
    packages=find_packages(exclude=['features']),
    install_requires=[
        "requests"
    ],
    extras_require={
    	'test': ['behave']
    },
)
