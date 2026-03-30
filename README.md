[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/zypA13510/unifi-asn-route-updater/docker-publish.yml?style=for-the-badge)](https://github.com/zypA13510/unifi-asn-route-updater/actions/workflows/docker-publish.yml)
[![GitHub Release](https://img.shields.io/github/v/release/zypA13510/unifi-asn-route-updater?include_prereleases&style=for-the-badge)](https://github.com/zypA13510/unifi-asn-route-updater/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/zypa13510/unifi-asn-route-updater?style=for-the-badge)](https://hub.docker.com/r/zypa13510/unifi-asn-route-updater)
[![Docker Image Size](https://img.shields.io/docker/image-size/zypa13510/unifi-asn-route-updater?style=for-the-badge)](https://hub.docker.com/layers/zypa13510/unifi-asn-route-updater/latest)
[![GitHub License](https://img.shields.io/github/license/zypA13510/unifi-asn-route-updater?style=for-the-badge)](https://github.com/zypA13510/unifi-asn-route-updater/blob/main/LICENSE)

## Installation

Download [ui-update-asn-routes.sh](ui-update-asn-routes.sh) and install the following dependencies (make sure they are available in `$PATH`):
- [curl](https://curl.se/)
- [jq](https://jqlang.org/)
- [aggregate6](https://github.com/job/aggregate6)

### Docker
```bash
docker pull zypa13510/unifi-asn-route-updater
```

**compose.yaml**:
```yaml
services:
  unifi-asn-route-updater:
    image: zypa13510/unifi-asn-route-updater:latest
    environment:
      ASNLOOKUP_API_TOKEN: 'token'
      UNIFI_API_TOKEN: 'token'
      UNIFI_HOST: 192.168.0.1
      #UNIFI_INSECURE: 1
      #VERBOSE: 1
```


## Configuration

The following options can be configured in environment variables:
| Name | Default value | Note |
| ---- | ------------- | ---- |
| `ASNLOOKUP_API_TOKEN` | ❗ (required) | [ASN Lookup](https://asnlookup.com/apidocs/) API key |
| `UNIFI_API_TOKEN` | ❗ (required) | UniFi Network Application API key. Create one on your UniFi console, under Control Plane &gt; Integrations. **Note**: this is different from the [Site Manager API](https://unifi.ui.com/api) key |
| `UNIFI_HOST` |Default gateway as indicated by `ip route show default 0.0.0.0/0` | Hostname / IP of your UniFi controller |
| `UNIFI_INSECURE` | 0 | Set this to 1 if your UniFi controller uses insecure HTTPS. Runs `curl` with `-k, --insecure` flag |
| `VERBOSE` | 0 | Set this to 1 to output extra debugging information |

Additionally, the following list of files can be configured in the Current Working Directory:
| Name | Note |
| ---- | ---- |
| cacert.pem | A PEM-encoded bundle of CA certificates, used to verify the UniFi controller. Runs `curl` with `--cacert ./cacert.pem` |

## Usage

1. On your UniFi controller, create a policy-based route and name it "AS&lt;AS number&gt; &lt;AS name&gt;". Optionally, you can append " IPv4" or " IPv6" to the rule name to filter out prefixes of the IP version specified. Examples of valid rule names:
   - `AS3356 LEVEL3`
   - `AS6939 HURRICANE IPv6`
2. Configure the policy-based route as needed, with the type of destination set to IP. While the list of IP addresses cannot be empty, you can use a placeholder value for the script to update later on (we use `192.0.2.0/32` for this purpose inside the script).
3. Run this script. You should see a list of additions and deletions printed to the console, and the up-to-date prefixes populated in your route.
4. (Optionally) Run this script periodically using cron or another scheduler.

### Caveats
- IP:Port combination is currently unsupported. All IP prefixes added by this script will have the port(s) unset (route all ports).
- Any "IP Address range" (in the start-end notation) will not be updated. Please avoid using them in the ASN routes unless you intend for them to remain untouched by this script for some reason.
- This script will try to look up any rule name in the "AS&lt;number&gt; " pattern. While "AS0123456789 obviously non-existent" is not valid, it does require one API call to validate and thus still consumes your API quota. On the other hand, multiple rules for the same ASN will be consolidated into a single API call.
- Disabled rules are excluded from lookup and update. If necessary, you can run this script after re-enabling them.
