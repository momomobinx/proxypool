# Change Log

(Change Log Link)[https://hub.docker.com/r/momomobinx/proxypool]

# Features
* Supports multiple types: ss, ssr, vmess, trojan, hysteria2,vless
* Scrapes from Telegram channels
* Parses subscription addresses
* Scrapes from publicly available web pages
* Automatically updates at scheduled intervals
* Configurable scraping sources through a configuration file
* Automatically checks the availability of nodes
* Provides clash and surge configuration files
* Provides ss, ssr, vmess, sip002 subscriptions
* Added streaming media detection feature, supports Netflix and Disney+

# About Streaming Media

* Supports Netflix and Disney+ streaming media detection.

* If supported, nodes will be renamed.

* Nodes that support Netflix will have netflix_ included in their names.

* Nodes that support Disney+ will have disney_ included in their names.

If you are using Clash, it is recommended to use the [Streaming Media Enhanced Rules](https://github.com/momomobinx/subrule/blob/main/netflix_for_node.ini) for better compatibility with streaming services.

![Stream](https://github.com/momomobinx/proxypool/blob/master/docs/im.png?raw=true)

## Run

### Docker

```shell
docker run -d --restart=always \
  --name=proxypool \
  -p 12580:12580 \
  -v /path/to/config:/config \
  momomobinx/proxypool \
  -c /config/config.yaml
```
### Docker-compose
```yaml
version: '3'
services:
  proxypool:
    image: momomobinx/proxypool:latest
    container_name: proxypool
    volumes:
      - /path/to/config:/config
    ports:
      - "12580:12580"
    restart: always
    command: -c /config/config.yaml
```
## Disclaimer
This project is for educational and reference purposes only. Users are advised to delete it after 24 hours. When using it, please refrain from violating local laws and regulations. It is prohibited to use this project for profit or engage in any other illegal activities. The project is not responsible for any consequences arising from its usage.