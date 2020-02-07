# OpenID Connect authentication plugin
Based on osTicket plugin "auth-oauth" by Jared Hancock from https://github.com/osTicket/osTicket-plugins

## License
GNU GENERAL PUBLIC LICENSE Version 2

## Installation

Install php-curl, php-simplexml

Run
```
php make.php hydrate
```

To pull all the dependencies.

Then run
```
php make.php build auth-gluu
```
to build the plugin

Drop `auth-gluu.phar` file to `include\plugins` directory of osTicket installation.

## Configuration

TODO
