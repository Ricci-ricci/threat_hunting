import geoip2.database


def enrich_with_geoip(alerts, db_path="GeoLite2-City.mmdb"):
    try:
        reader = geoip2.database.Reader(db_path)
    except FileNotFoundError:
        return alerts

    for alert in alerts:
        ip = alert.get("ip")
        if ip:
            try:
                response = reader.city(ip)
                alert["country"] = response.country.name
                alert["city"] = response.city.name
            except Exception:
                pass

    reader.close()
    return alerts
