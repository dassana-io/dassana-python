from setuptools import setup

setup(name='dassana',
      version='0.1',
      description='Dassana common data ingestion functions',
      url='https://github.com/dassana-io/dassana-python',
      author='Dassana',
      author_email='support@dassana.io',
      license='MIT',
      packages=['dassana'],
      install_requires=[
          'certifi',
          'requests'
      ],
      zip_safe=False)