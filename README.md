# OpenRelik Worker - amcache-evilhunter

## Description
OpenRelik worker integrates [AmCache-EvilHunter](https://github.com/cristianzsh/amcache-evilhunter) by **Cristian Souza** (GitHub: *cristianzsh*) to parse Windows `Amcache.hve`, extract execution artifacts (Program/File entries, SHA-1, timestamps), flag suspicious binaries, and optionally enrich via **VirusTotal**/**Kaspersky OpenTIP**. Outputs **JSON/CSV** plus a **TXT** log.

https://github.com/user-attachments/assets/6e8148e1-8b2f-4e8b-9077-67e499060276

Created from [OpenRelik Worker Template](https://github.com/openrelik/openrelik-worker-template). 
Refer to [OpenRelik docs](https://openrelik.org/guides/create-a-new-worker/).

## Deploy (docker-compose)
Add the below configuration to the OpenRelik `docker-compose.yml` file.

```yaml
  openrelik-worker-amcache-evilhunter:
    container_name: openrelik-worker-amcache-evilhunter
    image: ghcr.io/freedurok/openrelik-worker-amcache-evilhunter:latest
    restart: always
    environment:
        - REDIS_URL=redis://openrelik-redis:6379
        - OPENRELIK_PYDEBUG=0
        # Optional enrichments (set both env and checkbox in task config)
        - VT_API_KEY=${VT_API_KEY}            # VirusTotal API key
        - OPENTIP_API_KEY=${OPENTIP_API_KEY}  # Kaspersky OpenTIP API key
    volumes:
        - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-amcache-evilhunter"
    # ports:
    #   - 5678:5678  # For debug (if enabled)
```

## Task configuration (UI)

- VT Enable → adds `--vt` (requires `VT_API_KEY`).
- OpenTIP Enable → adds `--opentip` (requires `OPENTIP_API_KEY`).
- start (`YYYY-MM-DD`) → `--start`.
- end (`YYYY-MM-DD`) → `--end`.
- search (comma-sep) → `--search`.
- find_suspicious → `--find-suspicious`.
- missing_publisher → `--missing-publisher`.
- exclude_os → `--exclude-os`.
- only_detections → `--only-detections` (requires `VT_API_KEY`).

## Credits / Acknowledgments
Huge thanks to Cristian for the tool and research, this project stands on his work.
Repository: https://github.com/cristianzsh/amcache-evilhunter