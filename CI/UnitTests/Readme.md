# Unit testing

# Run unit tests:
1. Make sure you're within unit tests folder: cd ./CI/UnitTests/
2. Create virtual environment: virtualenv --python=python2.7 venv
3. Activate virtual environment: source ./venv/bin/activate
4. Install dependencies via pip: pip2 install -r requirements.txt
5. Now you'll need to get back to the repo's root folder: cd ../../
6. Make sure that everything works correctly by launching pytests: python2 -m pytest

## Coverage
1. Run script to generate new coverage report
a. *Nix: ./coverage.sh
b. Windows: coverage.bat
2. Go to main folder of the repo and open ./htmlcov/index.html file