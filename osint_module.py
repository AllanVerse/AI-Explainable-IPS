import requests

def get_threat_intelligence(ip):
    """Fetches real-time Geolocation and ISP data for a given IP."""
    
    # Skip private/local IPs since they don't exist on the public internet
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        return "Internal Network (LAN)"

    try:
        # Query the free IP-API service
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp", timeout=3)
        data = response.json()
        
        if data.get("status") == "success":
            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")
            isp = data.get("isp", "Unknown ISP")
            return f"{city}, {country} | ISP: {isp}"
        else:
            return "OSINT Query Failed (Private or Invalid IP)"
            
    except requests.exceptions.RequestException:
        return "OSINT API Unreachable"

# Quick test if you run this file directly
if __name__ == "__main__":
    test_ip = "185.156.177.10" # A known Russian IP range
    print(f"🔍 Tracing {test_ip}...")
    print(f"🌍 Result: {get_threat_intelligence(test_ip)}")