import requests
import socket
import math

MY_ADDR = requests.get('http://ifconfig.co/json').json()["ip"]


def main(targets, geo_results):
    """
    main function
    :return: tuple of (target domain, ttl, rtt, geological_dist)
    """
    targets_list = open(targets).read().splitlines()
    result = open(geo_results, 'w')

    for target in targets_list:
        dist = geo_dist_of(target)
        result.write('%s, %s\n' % (target, dist))
        print('Site: %s, distance: %s' % (target, dist))
    print('Probing complete')


def geo_dist_of(dest_name):
    """
    Source: https://gist.github.com/rochacbruno/2883505
    :return: geological distance between two points on earth in km
    """
    dest_addr = socket.gethostbyname(dest_name)

    long1, lat1 = coordinates_of(MY_ADDR)
    long2, lat2 = coordinates_of(dest_addr)

    earth_radius = 6371

    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(long2 - long1)
    a = math.sin(dlat / 2) * math.sin(dlat / 2) + math.cos(math.radians(lat1)) \
        * math.cos(math.radians(lat2)) * math.sin(dlon / 2) * math.sin(
        dlon / 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return int(earth_radius * c)


def coordinates_of (ip_addr):
    """
    find longitude and latitude of an IP address
    :return: X-Y coordinates
    """
    json_request = requests.get('http://freegeoip.net/json/%s' % ip_addr).json()
    return json_request['longitude'], json_request['latitude']


if __name__ == "__main__":
    main("targets.txt", "geo_results.csv")
