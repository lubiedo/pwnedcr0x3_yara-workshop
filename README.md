# YARA Rules: gotta catch 'em all!

PwnedCR 0x3 (2020) workshop.

Language: spanish.

## Requirements
* OS: Linux (preferably)
* Internet access
* Software: Docker installed
* Basic C and x86 assembly knowledge level

## Build the container
A Dockerfile is provided with all that you need for the workshop :)
To build:
```
cd src/ && docker build -t yara-workshop .
```

## Run the container
Simple as:
```
docker run --privileged -ti --rm yara-workshop:latest
```
You will land on the shell to start working.

## Malware:
Family | Type | Rule | Hash (SHA256) | Location |
--- | --- | --- | --- | ---
Dummy | Example | N/A | N/A | [source](src/dummy)
WannaCry | Ransomeware | RANSOM_MS17-010_Wannacrypt.yar | aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c | [zip](src/files/malware/aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c.zip)
Dridex | Maldoc | Maldoc_Dridex.yar | db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210 | [zip](src/files/malware/db788d6d3a8ed1a6dc9626852587f475e7671e12fa9c9faa73b7277886f1e210.zip)
