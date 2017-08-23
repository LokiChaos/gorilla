# gorilla
SSL validation based on vhosts

<img src="https://github.com/maurodelazeri/gorrilla/blob/master/gorilla.png">

## Possible outputs

```
./gorilla
OK - All certs are updated.
```

```
./gorilla -dirs "/var/apache2/vhosts" -daysexpiration 5
WARNING - Checked 1 cert that need to be updated, please check for more details /etc/certificates.lock
```

## Dynamic parameters

```
go run gorilla.go -help
  -daysexpiration int
    	Number of days before warning (default 15)
  -dirs string
    	Directories be checked to find certs (default "/etc/nginx/sites-enabled,/etc/apache2/sites-enabled,/etc/nginx/vhosts.d,/etc/apache2/vhosts.d")
  -lockfike string
    	Lock file location (default "/etc/certificates.lock")
  -verbosity int
    	0 = only errors, 1 = important things, 2 = all (default 2)
```
