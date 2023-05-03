Widget Script
=============

A script for creating templates for widgets using Jinja2 template engine!

To run the script over all the integrations in the marketplace run the next command
from the `SiemplifyMarketPlace/Common/Scripts/WidgetTemplateScript/` directory

On macOS and Linux:
```shell
python3 main.py --all
```
On Windows:
```shell
python main.py --all
```


## Requirements

To run the script you will need ***Python version 3.10+***

All other libraries and versions are specified in the `requirements.txt` file inside
`SiemplifyMarketPlace/Common/Scripts/WidgetTemplateScript/`


To install the requirements run

On macOS and Linux:
```shell
pip3 install -r requirements.txt
```
On Windows:
```shell
pip install -r requirements.txt
```

## Widgets Structure

### Action widget

For an integration to have widgets for its actions,
it must contain two folders inside the integration's folder:
  - Widgets
  - WidgetsScripts

Example:
```
SomeIntegration
│    ActionsDefinitions
│    ActionsScripts
│    ConnectorsDefinitions
│    ConnectorsScripts
│    Dependencies
│    Managers
│    ...
│
└─── Widgets
│    │    EnrichAction.json
│    │    QueryAction.json
│    │    ...
│ 
└─── WidgetsScripts
     │    EnrichAction.hmtl
     │    QueryAction.html
     │    ...
     │
     └─── WidgetsElements
          │    optional_common_template.html
          │    optional_common_code.js
          │    ...
          │    
          └─── EnrichAction
          │    │    widget_data_config.yaml
          │    │    widget_imports_config.yaml
          │    │    ...
          │
          └─── QueryAction
               │    widget_data_config.yaml
               │    widget_imports_config.yaml
               │    SomeTemplateFile.html
               │    SomeScriptFile.js
               │    SomeStyleFile.css
               │    ...
```
In the `Widgets/` directory will be all the widgets metadata *.json* files.

In the `WidgetsScripts/` top level will be the complete flat *.html* files that the script
outputs and that the platform will use.
Besides that, there will be a `WidgetsElements` directory that will contain a subdirectory
for each action that has a widget in the integration and uses the script for generating tha flat *.html* file.
The `WidgetsScripts/WidgetsElements` folder may also contain files with shred code that 
are only specific to this integration. Those can be imported via the `widget_imports_config.yaml`.

Each "action widget folder" inside a `WidgetElements` directory must include at least
two configuration files:
  - `widget_data_config.yaml` for configuring the imports that the script will make
  - `widget_imports_config.yaml` for configuring the data that will be used to resolve the template

Besides the configuration files, the "action widget folder" can include other script, style and template
files that might be used to create its specific widget.

### Widgets Common

The WidgetsCommon folder contains a folder per widget-type that needs a template, the BaseWidget folder
and may contain a Common folder for files of common code that isn't unique for a specific widget type, 
but doesn't need to be imported automatically like everything in the BaseWidget folder.

The content of BaseWidget is the base template that al other template should extend, and common libraries of components, styles and scripts.
All BaseWidget's files are automatically imported even without being included in a `widget_imports_config.yaml` file of a widget,
so the template can use everything inside out of the box.

## Script Parameters

```commandline
usage: python3 main.py [-h] [-a] [-i INTEGRATIONS [INTEGRATIONS ...]] [-g IGNORE_INTEGRATIONS [IGNORE_INTEGRATIONS ...]] [-p]

options:
  -h, --help            show this help message and exit
  -a, --all             Use this flag if you want the script to go over all the integrations in the marketplace. If both --integrations and --all are used, --all will override.
  -i INTEGRATIONS [INTEGRATIONS ...], --integrations INTEGRATIONS [INTEGRATIONS ...]
                        One or more specific integrations in the marketplace for the script to run on. If both --integrations and --all are used, --all will override. If an integration is both in -i and in -g, -g
                        will override. Multiple files can be provided as such: -i integration1 integration2
  -g IGNORE_INTEGRATIONS [IGNORE_INTEGRATIONS ...], --ignore-integrations IGNORE_INTEGRATIONS [IGNORE_INTEGRATIONS ...]
                        One or more specific integrations in the marketplace for the script to skip when running. If both --integrations and --all are used, --all will override. If an integration is both in -i and
                        in -g, -g will override. Multiple files can be provided as such: -g integration1 integration2
  -p, --prettify   If used, an HTML parser will parse the flat widget end results to "prettify" it. The current defined parser is python's lxml.html parser
```

## Configuring The template

To configure the template for producing the right HTML file for your widget,
there are two different configuration files.

The configuration file is a *.yaml* file which is a superset of *.json* files.
This means that writing JSON content in there is totally valid, but using YAML's
simplifying features is advised over regular JSON for readability purposes.

### Widget Imports Config

  This configuration file deals with which files to use for the template.

  It's divided to seven main sections:
```yaml
main_template_name: ...

common_imports:
  ...
  
local_widget_imports:
  ...

local_integration_imports:
  ...

custom_imports:
  ...

script_functions:
  ...

styles_classes:
  ...
```
  
#### `main_template_name`:

(string) This is the name of the main template that will be used.
The name must contain the file's extension as all files in the configuration file,
and must be one of the templates that are being imported in any of the other sections.
 
For example:
  ```yaml
main_template_name: QueryWidgetTemplate.html
  ```  

---

#### `common_imports`: 

(dict) Under this key you will import everything that you require from
`SiemplifyMarketPlace/Common/SourceCode/Widgets/WidgetsCommon/` directory.

This can be done by specifying a name of any of the folders inside, and choosing the files that you want to import.

For example:
  ```yaml
  common_imports:
    # This is a folder in WidgetsCommon/
    QueryWidget:
      # These files exist in that folder
      files:
        - QueryWidgetTemplate.html
        
    EnrichWidget:
      files:
        - EnrichWidgetScripts.js
        - EnrichWidgetStyles.css
  ```
If all the files in a folder needs to be imported, you can specify a special key `import all`,
with a boolean value (yes, true, True and all other YAML available booleans) to indicate whether you need to import all.

For example:
```yaml
common_imports:
  QueryWidget:
    import_all: yes
```
Note:
  - Specifying `import_all: no` is the same as not having the key at all.
  - If `import_all: yes`, then it will override any other `files:` that are might also be specified.
  - The files' names must include their extension.

---

#### `local_widget_imports`: 

(dict) Under this key you will import everything that you require from
`Integrations/{integration_identifier}/WidgetsScripts/WidgetsElements/{action_name}/` directory.

This can be done by specifying a name of any of  the files that you want to import. 
For example:
```yaml
local_widget_imports:
  # These files exist in that folder
  files:
    - GetTechniquesMitigationsScripts.js
    - GetTechniquesMitigationsStyles.css
```
If all the files in a folder needs to be imported, you can specify a special key `import all`,
with a boolean value (yes, true, True and all other YAML available booleans) to indicate whether you need to import all.
  
For example:
```yaml
local_widget_imports:
  import_all: yes
```
Note:
  - Specifying `import_all: no` is the same as not having the key at all.
  - If `import_all: yes`, then it will override any other `files:` that are might also be specified.
  - The files' names must include their extension.

---
  
#### `local_integration_imports`: 

(dict) Under this key you will import everything that you require from
`Integrations/{integration_identifier}/WidgetsScripts/WidgetsElements/` directory.

This can be done by specifying a name of any of the files you want to import.

For example:
```yaml
local_integration_imports:
  # These files exist in that folder
  files:
    - MitreAttackCommonWidgetScripts.js
```
If all the files in a folder needs to be imported, you can specify a special key `import all`,
with a boolean value (yes, true, True and all other YAML available booleans) to indicate whether you need to import all.
  
For example:
```yaml
local_integration_imports:
  import_all: yes
```
Note:
  - Specifying `import_all: no` is the same as not having the key at all.
  - If `import_all: yes`, then it will override any other `files:` that are might also be specified.
  - The files' names must include their extension.

---
  
#### `custom_imports`: 

(list) Under this key you can import any specific files by path.
There are multiple shortcuts to for useful paths:
- If the path starts with `WidgetsCommon/` it will generate the full up until the "WidgetsCommon" folder.
- If the path starts with `Integrations/` it will generate the full up until the "Integrations" folder.
- If the path starts with `SiemplifyMarketPlace/` or doesn't start with any of the other shortcuts,
  it will default to starting from "SiemplifyMarketPlace" and continue to find the rest of the path specified.

This can be done by specifying the full paths of the files that you want to import.

For example:
```yaml
custom_imports:
  - SiemplifyMarketPlace/Common/TIP/TIPCommon/{some_file}.html
  - Common/TIP/TIPCommon/{some_file}.js
  - WidgetsCommon/QueryWidget/QueryWidgetTemplate.html
  - Integrations/GoogleChronicle/WidgetsScripts/WidgetElements/LookupSimilarAlerts/LookupSimilarAlertsStyle.css
```
Note:
  - The files' names must include their extension.
 
---
  
#### `script_functions`: 

(dict) Under this key you can import any specific functions from a *.js* file by name.

This can import functions that are written in the next format:
```javascript
function functionName(...) {
    ...
}
```
The name must be equal, but the parameters and body of the function doesn't matter

There are multiple shortcuts to for useful paths:
  - If the path starts with `WidgetsCommon/` it will generate the full up until the "WidgetsCommon" folder.
  - If the path starts with `Integrations/` it will generate the full up until the "Integrations" folder.
  - If the path starts with `SiemplifyMarketPlace/` or doesn't start with any of the other shortcuts,
    it will default to starting from "SiemplifyMarketPlace" and continue to find the rest of the path specified.

This can be done by specifying a path of any file, and choosing the functions that you want to import. 

For example (see `custom_imports` above for more shortcuts examples):
```yaml
script_functions:
  Common/TIP/TIPCommon/{some_file}.js:
    functions:
      - nFormatter
      - arrayToCSV
```
If all the file's content needs to be imported, you can specify a special key `import all`,
with a boolean value (yes, true, True and all other YAML available booleans) to indicate whether you need to import all.

For example:
```yaml
script_functions:
  import_all: yes
```
Note:
  - Specifying `import_all: no` is the same as not having the key at all.
  - If `import_all: yes`, then it will override any other `files:` that are might also be specified.
  - The files' names must include their extension.
  
---
  
#### `styles_classes`: 

(dict) Under this key you can import any specific functions from a *.css* file by name.

This can import functions that are written in the next format:
```css
#aClassNameIncludingDotsAndSuch .evenAnotherOne  ::last-one.forReal {
    ...
}
```
The name must be equal, but the body of the class doesn't matter

There are multiple shortcuts to for useful paths:
- If the path starts with `WidgetsCommon/` it will generate the full up until the "WidgetsCommon" folder.
- If the path starts with `Integrations/` it will generate the full up until the "Integrations" folder.
- If the path starts with `SiemplifyMarketPlace/` or doesn't start with any of the other shortcuts,
  it will default to starting from "SiemplifyMarketPlace" and continue to find the rest of the path specified.

This can be done by specifying a path of any file, and choosing the functions that you want to import.

For example (see `custom_imports` above for more shortcuts examples):
```yaml
styles_classes:
  Integrations/GoogleChronicle/WidgetsScripts/WidgetElements/LookupSimilarAlerts/LookupSimilarAlertsStyle.css:
    classes:
      - .logo
      - .notable table tr th
```
If all the file's content needs to be imported, you can specify a special key `import all`,
with a boolean value (yes, true, True and all other YAML available booleans) to indicate whether you need to import all.

For example:
```yaml
styles_classes:
  import_all: yes
```
Note:
  - Specifying `import_all: no` is the same as not having the key at all.
  - If `import_all: yes`, then it will override any other `files:` that are might also be specified.
  - The files' names must include their extension.
 
---

### Widget Data Configuration

The `widget_data_config.json` file will require a different set of keys and values to be passed
based on the template the are used to create the widget. Every template requires different variables, thus 
the value that you pass may differ.

Please look at the `readme.md` file of the specific widget-type template
that you want to use for the details about the data options.
    