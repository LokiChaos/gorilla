# gorilla
SSL validation based on vhosts

<img src="https://github.com/maurodelazeri/gorrilla/blob/master/gorilla.png">

## Possible outputs

```
./gorilla
OK - All certs are updated.
```

or

```
./gorilla
WARNING - 1 certs need to be updated, please check: /etc/certificates.lock
exit status 1
```

## Directories for checking

Just add to the array the directories you want to check

```
checkingDirs := []string{"/etc/nginx/sites-enabled", "/etc/apache2/sites-enabled", "/etc/nginx/vhost.d", "/etc/apache2/vhost.d"}
```
