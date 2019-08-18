# urlbuster
Basic web security scanner. This tool is an analog of dirbuster written in go.

## Project features

- Scans remote host for known files taken from the signatures.txt file
- Use heuristics to scan for sensitive files

## Build

```
./build.sh
```

## Adding new signatures to signatures.txt

After making changes to signatures.txt file make sure it is sorted and duplicates removed.

```
sort -u -o signatures.txt signatures.txt
```
