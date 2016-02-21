from setuptools import setup

setup(name='concorde',
      version='0.2',
      description='ACME client commandline tool and library',
      url='https://github.com/frutiger/concorde',
      author='Masud Rahman',
      license='MIT',
      packages=['concorde'],
      install_requires=[
          'cryptography',
          'requests',
      ],
      entry_points={
          'console_scripts': ['concorde=concorde.__main__:main'],
      })

