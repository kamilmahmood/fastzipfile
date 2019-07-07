from setuptools import setup
from setuptools import Extension
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

decrypter = Extension('_zipdecrypter', ['src-c/_zipdecryptermodule.c'])

setup(
      name='fastzipfile',
      version='v1.0.0b',
      description='Read password protected Zips 100x faster',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/kamilmahmood/fastzipfile',
      author='Kamil Mahmood',
      author_email='kamil.mahmood@outlook.com',
      classifiers=[
        'Development Status :: Beta',
        'Intended Audience :: Developers',
        'Topic :: Decryption :: Zip Decryption',
        'License :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='zipfile decryption',
    python_requires='>=3.0, <4',
    py_modules=['fastzipfile'],
    ext_modules=[decrypter]
)
