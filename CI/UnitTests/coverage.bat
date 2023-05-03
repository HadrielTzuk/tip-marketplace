echo "Launching new coverage report"
coverage run -m pytest
coverage report
coverage html
echo "HTML version is available in ./htmlcov/index.html"