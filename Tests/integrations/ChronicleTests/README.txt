Modules required to run:
    1. pytest
    2. pytest-mock
    3. pytest-cov
    4. google
    5. google-auth
    6. regex
    7. pytz

Required changes in code that needs to be done for the tests to work, until they will be added to the integrations:
    1. TIPCommon, remove the dot on line 10:
       from .DataStream import DataStreamFactory -> from DataStream import DataStreamFactory

    2. GoogleChronicleManager, change import statement to be more specific until the name of the 'exceptions' module is changed.
       import exceptions -> from ..Managers import exceptions

    3. GoogleChronicle/Managers/utils, comment out the import of EnvironmentCommonOld and the function that uses it
       until it gets removed.


To run with coverage you should edit the configuration of running a single test with the next parameters: "--cov SiemplifyMarketPlace test_google_chronicle_manager.py --cov-report html"
And then it will run all the tests in the module and will produce an HTML file with the coverage results (For the manager module only)

To remove lines from coverage check, mark the line with "  # pragma: no cover"
If the line defines a new code block (e.g. def f():  # pragma: no cover) then
the whole block is excluded.

**NOTE!
Some parameters such as ticket_id are required to be in the chronicle instance and cannot be created as part of the test!
Please look at the constants and ids that are written in the code.

