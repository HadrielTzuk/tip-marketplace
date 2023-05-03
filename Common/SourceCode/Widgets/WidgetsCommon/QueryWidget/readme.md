# Data Configuration

The `widget_data_config.yaml` file of a query widget can be divided into 3 main
parts:
- JSON Structure Parameters
- HTML Structure Parameters
- Table Structure Parameters

## JSON Structure Parameters

```yaml
json_result_list: '[{stepInstanceName}.JsonResult]'

json_result_has_entities: yes
entity_key: Entity
entity_result_list_path: EntityResult.mitigations

count: count_key
count_fn: getArrayLength

get_data_to_iterrate: get_data_for_iteration
```

Each data configuration file must receive the Json result from the action that ran it
using Chronicle SOAR placeholder mechanism (placeholder logic and possibilities will not be covered here).

The placeholder that is provided must always be evaluated to an array.
If the result type itself is the required array you can put `json_result_list: '[{stepInstanceName}.JsonResult]'`
or remove this key from the configuration, as this is the default value of this key.

If for example the result is a dictionary with a key that holds the required array, you can
pass `json_result_list: '[{stepInstanceName}.JsonResult| "path.to.key"]'` for example.


### JSON Result Structure

There are a few different Json structures that are supported by the template
out of the box.
This section relates to the next keys:
- `json_result_has_entities` (boolean)
- `entity_key` (string)
- `entity_result_list_path` (string)

#### No Entities

A dictionary that has a key that contains the main array which needs to be counted and iterate over.

```json
{
    "key": [...]
    ...
}
```

An array of dictionaries that we want to count and iterate over.

The length of of the array will be counted, and the widget will go over each element of the array
to take data for the table.
```json
[
    {...},
    {...}
]
```

#### With Entities

A list of Entity object, where each entity result is an array of results that needs to be counted, iteration is done on each entity

```json
[
    {
        "Entity": ...
        "EntityResult": [...]
    },
    {
        "Entity": ...
        "EntityResult": [...]
    }
]
```

A list of Entity object, where each entity result has a key to an array of results that needs to be counted, iteration is done on each entity


```json
[
    {
        "Entity": ...
        "EntityResult": {
            "key": [...]
        }
    },
    {
        "Entity": ...
        "EntityResult": {
            "key": [...]
        }
    }
]
```

If the result has entities, mark `json_result_has_entities: yes`. If not, mark
`json_result_has_entities: no` or remove this key from the configuration.

If the result has entities, the key for the entity identifies, as well as the entity result key
needs to be specified via the keys `entity_key` and `entity_result_list_path`.

Note:
- If the type of entity result is not an array, specify the path to the array using the dot product.
  e.g. `entity_result_list_path: EntityResult.mitigations`
- When `entity_key` and `entity_result_list_path` are not specified,
  they will be filled with `Entity` and `EntityResult` as default values respectively
- For any other structure of JsonResult, please see the "Other Types of JSON Structures" section

### Other Types of 'JSON Structures' section

This section relates to the next keys:
- `count` (string)
- `count_fn` (string)
- `get_data_to_iterrate` (string)

If the Json result of doesn't fall in the out of the box types, or if the iteration itself should be
done differently, or something else should be counted instead of the default options, the behavior can be customized.

#### Custom Counting Method

The `count` key can be used to access a specific key in the Json result (or be a placeholder)
and that value will be displayed as the count.

For example:
```yaml
count: '[{stepInstanceName}.JsonResult| "count"]'
```

For total customization, the `count_fn` key can be specified with a name of a function (don't forget to import the function itself)
that receives the Json result and outputs the count. If the `count` key is also specified,
then the count key/placeholder from the Json result will be passed to the count function.

#### Custom Data Iteration

The `get_data_to_iterrate` can be specified with placeholder or a name of a function (don't forget to import the function itself)
that takes the json_result_list and outputs the data that the $.each(this, ...) method will iterate over

## HTML Structure Parameters

```yaml
main_text_singular: MITIGATION
main_text_plural: MITIGATIONS
main_text: SIMILAR ALERTS FOUND
import_svg_from_integration: yes
logo_svg:
  class: logo-svg
  width: 64
  height: 25
  viewBox: 0 0 92 25
  fill: none
  xmlns: http://www.w3.org/2000/svg
  paths:
    - d: M0 25H5.41176L8.38824 9.73684L14.3412 25H18.1294L24.0824 9.73684L27.3294 25H32.7412L27.3294 0H22.7294L16.2353 15.2632L10.0118 0H4.87059L0 25Z
      fill: white
      
    - d: M38.6941 25V0H34.0941V25H38.6941Z
        fill: white

```

### Main Text

If the main text is static, then it can be passed through the `main_text` key.

If the text should chance between singular and plural depends if the count is 1 or more,
then use the `main_text_singular` and `main_text_plural` keys instead.

### Logo Configuration

#### Auto-Loading

To load the logo automatically, use the key `import_svg_from_integration: yes`.
This will import the value from the key `'SVGImage'` in the integration's `.actiondef` file.

#### Manual Configuration

If needed, the SVG can be configured manually using the `logo_svg` key.
Each key in the logo-svg dictionary (except for `paths`) will be included in the `<svg>` tag.

The above configuration will result in
```html
<svg class="logo-svg" width="64" height="25" viewBox="0 0 92 25" fill="none" xmlns="http://www.w3.org/2000/svg">
```

You can add any keyword with any value and it will show up.

The same goes for all keys in `paths` and each path tag in the svg tag.

The example configuration above will result in
```html
<svg class="logo-svg" width="64" height="25" viewBox="0 0 92 25" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path
      d="M0 25H5.41176L8.38824 9.73684L14.3412 25H18.1294L24.0824 9.73684L27.3294 25H32.7412L27.3294 0H22.7294L16.2353 15.2632L10.0118 0H4.87059L0 25Z"
      fill="white"/>
    <path
      d="M38.6941 25V0H34.0941V25H38.6941Z"
      fill="white"/>
</svg>
```

## Table Structure Parameters

```yaml
key_not_found_display_value: Data Not Found
auto_map_columns: no
table_data:
  - header: External ID
    th_style:
      width: 25%
      
    value:
      is_link: yes
      url_value: '[{stepInstanceName}.JsonResult| "cbn_url"]'
      prefix_with_keys_names: yes
      only_non_empty_values: yes
      collapse_long_text: yes
      check_field: yes
      remove_special_symbols: yes
      pass_to_function: createTitleId
      function_parameters:
        - a
        - b
      keys_to_display:
        - external_references

  - header: Mitigation
    th_style:
      width: 30%

    value:
      keys_to_display:
        - name
```

The `key_not_found_display_value` key let you choose what would be the message that will
be displayed if a key wasn't found in the JSON.
If this key is not specified the default value 'N/A' will be used.

If the `auto_map_columns` flag is used, the json will be generated using all the keys
of the array of JSONs as column headers and their values as the column values, disregarding
all othe specifications under `table_data`.

Each item inside the `table_data` array will control a column in the resulting table.

The `header` key will be the header, and the `th_style` will take the keywords and values and put them in the
`<th>` tag.

The `value` key controls what data will be put in the table.
In `keys_to_display` you can list the keys in the Json result that will be displayed in the data cell.
If there are more than one key, their values will be combined separated with line breaks.

### Data Cell Configuration

This section relates to the next keys:
- `is_link` (boolean)
- `url_value` (string)
- `prefix_with_keys_names` (boolean)
- `only_non_empty_values` (boolean)
- `collapse_long_text` (boolean)
- `check_field` (boolean)
- `remove_special_symbols` (boolean)
- `pass_to_function` (string)
- `function_parameters` (array[string])

There are some out of the box logics for manipulating the data cell's value.

#### `is_link` and `url_value`

If the value needs to be a link, the `is_link` key can be switched on, and the value will be wrapped
with an anchor with an 'href'. The displayed value will be that of the keys in `keys_to_display`
and the actual URL value will be the value of the `url_value` key.
`url_value` can be either a placeholder or a key in the iterated element.

#### `prefix_with_keys_names`

If this key is active, the value of the key will be prefixed with its name, e.g.
```json
{
    "key_name": "name"
}
```
Will transform to
```html
<td>key_name: name</td>
```

#### `only_non_empty_values`

If this is passed as true, The value will be added only if it contains vlaue

#### `collapse_long_text`

If the field is a long text (that can reach more than 250 characters) pass this argument to add
the logic of collapsing long text in this key.


#### `check_field` and `remove_special_symbols`
Each of this keys is a function (the implementation can be found in `BaseWidget/CommonScripts.html`).
The value will be passed through the function if the correlating key is set to true.


#### `pass_to_function` and `function_parameters`

If the value from the Json result needs to be parsed in a way that is not supported out of the box,
you can specify a name of a function that takes the value as its first parameter and outputs the correct value to display
(don't forget to import the function itself).

If the function needs other parameters, pass them in `function_parameters` and they'll be added to the
function call.

Note:
- All boolean parameters have a default value of 'false' if not defined in the configuration.