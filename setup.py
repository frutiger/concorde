from setuptools import setup

setup(name='concorde',
      version='0.13.1',
      description='ACME client library, cli tool, and automation tool',
      url='https://github.com/frutiger/concorde',
      author='Masud Rahman',
      license='MIT',
      packages=[
          'concorde',
          'concorde.acme',
          'concorde.cli',
          'concorde.crypto',
          'concorde.shaman',
      ],
      install_requires=[
          'cryptography',
          'requests',
      ],
      entry_points={
          'console_scripts': [
              'concorde=concorde.cli.__main__:main',
              'shaman=concorde.shaman.__main__:main',
          ],
      })

