import streamlit as st
import ipaddress
import requests
from datetime import datetime



@st.cache_data(ttl=86400)
def get_cloud_provider_ranges():
    providers = {
        "AWS": {
            "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
            "parser": lambda data: (
                [p["ip_prefix"] for p in data["prefixes"]] +
                [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", [])]
            )
        },
        "Google Cloud": {
            "url": "https://www.gstatic.com/ipranges/cloud.json",
            "parser": lambda data: (
                [p["ipv4Prefix"] for p in data["prefixes"] if "ipv4Prefix" in p] +
                [p["ipv6Prefix"] for p in data["prefixes"] if "ipv6Prefix" in p]
            )
        },
        "Cloudflare": {
            "url": "https://api.cloudflare.com/client/v4/ips",
            "parser": lambda data: (
                data["result"]["ipv4_cidrs"] +
                data["result"]["ipv6_cidrs"]
            )
        },
        "Oracle Cloud": {
            "url": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
            "parser": lambda data: [
                c["cidr"] for r in data["regions"] for c in r["cidrs"]
            ]
        }
    }

    ip_ranges = {}
    for provider, config in providers.items():
        try:
            response = requests.get(config["url"], timeout=10)
            response.raise_for_status()
            data = response.json()
            ip_ranges[provider] = config["parser"](data)
        except Exception as e:
            st.warning(f"⚠ Could not fetch {provider} ranges: {str(e)}")
            ip_ranges[provider] = get_fallback_ranges(provider)

    return ip_ranges


def get_fallback_ranges(provider):
    fallbacks = {
        "AWS": [
            "18.208.0.0/13", "52.95.245.0/24", "54.240.0.0/18",
            "2600:1f00::/40", "2600:1f14::/35"
        ],
        "Google Cloud": [
            "8.8.8.8/32", "8.8.4.4/32", "34.0.0.0/15",
            "2600:1900::/35", "2001:4860::/32"
        ],
        "Cloudflare": [
            "103.21.244.0/22", "104.16.0.0/13", "172.64.0.0/13",
            "2400:cb00::/32", "2606:4700::/32"
        ],
        "Oracle Cloud": [
            "129.213.0.0/16", "134.70.0.0/17", "140.91.0.0/16",
            "2603:10e1::/36", "2620:10f::/36"
        ]
    }
    return fallbacks.get(provider, [])


def validate_ip(ip_str):
    cleaned_ip = ip_str.strip().replace(',', '').replace(' ', '.')
    try:
        ipaddress.ip_address(cleaned_ip)
        return cleaned_ip
    except ValueError:
        return None


def main():
    st.set_page_config(page_title="IP2Cloud", page_icon="☁")
    st.title("☁ IP2Cloud - Cloud Provider IP Checker")
    st.markdown("Check if an IP address belongs to major cloud provider networks")

    ip_ranges = get_cloud_provider_ranges()

    with st.form("ip_check"):
        ip_input = st.text_input("Enter IP Address", placeholder="e.g. 8.8.8.8 or 2001:4860:4860::8888")
        submitted = st.form_submit_button("Check IP")

    if submitted:
        valid_ip = validate_ip(ip_input)
        if not valid_ip:
            st.error("❌ Invalid IP address format. Examples: 8.8.8.8 or 2600:1900:4000::")
            return

        results = []
        for provider, ranges in ip_ranges.items():
            for cidr in ranges:
                try:
                    if ipaddress.ip_address(valid_ip) in ipaddress.ip_network(cidr):
                        results.append({
                            "Provider": provider,
                            "CIDR Range": cidr,
                            "IP Version": "IPv4" if "." in cidr else "IPv6"
                        })
                        break
                except ValueError:
                    continue

        if results:
            st.success("✅ IP found in these cloud provider ranges:")
            st.table(results)

            if valid_ip in ("8.8.8.8", "8.8.4.4"):
                st.info("ℹ Note: 8.8.8.8 and 8.8.4.4 are Google Public DNS servers")
        else:
            st.info("ℹ IP not found in any known cloud provider ranges.")

    st.sidebar.title("Provider Status")
    for provider, ranges in ip_ranges.items():
        status = "✅ Live" if len(ranges) > 10 else "⚠ Fallback"
        st.sidebar.markdown(f"{provider}: {status} ({len(ranges)} ranges)")


if __name__ == "__main__":
    main()
