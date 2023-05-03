# MILS - MarketPlace Integration Loader Service 
##(v1.0)
### Intro
Internal Siemplify tool for MarketPlace development, to update integrations code
in a Siemplify instances in real time.  

This tool updates an entire integration file from your local marketplace directory, into the integrations cache in the
Siemplify instance, using the `Upload Package` feature in Siemplify's IDE.

*NOTE- 
At this moment, this service is only supported on MacOS & Linux/UNIX operating systems.

### Installation
1. Open a terminal in the script directory.  
from the repo's root:  
`cd Common/Scripts/MarketplaceIntegrationLoaderScript`
2. Run `./setup.sh`
3. When prompted, type in the Siemplify instance URL, user name, and password 
to access the instance from the login page.  
E.g.
```shell
Enter Siemplify instance API Root: 
https://localhost:8443                    # user input
Enter Username for Siemplify instance:  
user@email.com                            # user input
Enter Password for Siemplify instance:    
                                          # user input. password is entered in secret mode
saving updated configuration settings...
```
4. You will be prompted again to run a command in the terminal to apply 
the alias created for the service  
On glinux OS, the command will be something like: `source /your/home/path/.bashrc`  
On MacOS, it will be similar to `source /your/home/path/.zshrc`
5. After that the installtion will be completed, and you will be prompted 
that you can run `mils` in the terminal 

### How-To Use

```shell
usage: mils [-h] [-i [INTEGRATION ...]] [-s | --save-zip | --no-save-zip] [-v]

An interactive service which uploads integrations code from the local "Integrations" repository, into Siemplify machine.

options:
  -h, --help            show this help message and exit
  -i [INTEGRATION ...], --integration [INTEGRATION ...]
                        upload the integration code to Siemplify machine.multiple integrations can be uploaded at-once
  -s, --save-zip, --no-save-zip
                        saves the created ZIP file to local file-storage
  -v, --version         show program's version number and exit

When uploading an integration code, use the integration identifierwithout any whitespaces. The integration identifier can be case-insensitive.
```
   
   
#### Upload integration code
Use the `-i` option followed by the integration identifier, to upload that 
integration code as a ZIP file to the instance IDE.  
You should see it as installed in the MarketPlace as well after a refresh.  
*NOTE - the integration identifier should be whithout whitespace!  
E.g. `Google Chronicle` --> `GoogleChronicle`
- example: `mils -i virustotalv3`

the `-i` option also supports multiple integrations.
- example: `mils -i virusTotalV3 GoogleChronicle Okta`

You can also add the `-s` option to save all the ZIP files created in  your local 
`MILS/tmp` folder.

- example: `mils -s -i virustotalv3` OR `mils -i virustotalv3 -s`  
*NOTE - By default the service deletes all created zip files after every execution.
Move/ copy files from the local `MILS/tmp` folder if you don;t it to be deleted.