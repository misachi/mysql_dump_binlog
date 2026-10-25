# mysql_dump_binlog
Read and parse binlog contents(INSERT/DELETE/UPDATE)

## Usage
```
cargo run -- -b /var/lib/mysql/binlog.000004 -d /var/lib/mysql
```

Where `-b` flag points to binlog file and `-d` flag is the location of MySQL data directory
