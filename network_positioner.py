import math
import numpy as np

def get_ip_display_positions(info):

    ip_to_position = dict()

    subnet_centers = np.random.uniform([0, 0], [1500, 1500], size=(len(info["subnets"]), 2))

    for subnet, subnet_position in zip(info["subnets"], subnet_centers):
        
        subnet_data = info["subnets"][subnet]

        angle = 0.0
        SUBNET_SIZE = len(subnet_data["entities"])
        RADIUS = math.sqrt(SUBNET_SIZE) * 40.0
        for ip in subnet_data["entities"]:

            x = subnet_position[0] + RADIUS * math.cos(angle * (math.pi / 180.0))
            y = subnet_position[1] + RADIUS * math.sin(angle * (math.pi / 180.0))

            ip_to_position[ip]  = (x, y)
            angle += 360.0 / SUBNET_SIZE

    return ip_to_position