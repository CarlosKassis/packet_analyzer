import math
import numpy as np

def get_ip_display_positions(info):

    #np.random.seed(1000)

    ip_to_position = dict()


    REAL_SUBNET_COUNT = len([subnet for subnet in info["subnets"] if info["subnets"][subnet]["type"] == "real"])
    GUESSED_SUBNET_COUNT = len(info["subnets"]) - REAL_SUBNET_COUNT

    # Subnets gathered by info go more towards the middle
    real_subnet_centers = np.random.uniform([0, 0], [700, 700], size=(REAL_SUBNET_COUNT, 2))
    guessed_subnet_centers = np.random.uniform([0, 0], [3000, 3000], size=(GUESSED_SUBNET_COUNT, 2))
    real_subnet_to_center = dict((subnet, real_subnet_centers[index]) for (subnet, index) in zip(info["subnets"], range(REAL_SUBNET_COUNT)))
    guessed_subnet_to_center = dict((subnet, guessed_subnet_centers[index]) for (subnet, index) in zip(info["subnets"], range(GUESSED_SUBNET_COUNT)))

    for subnet in info["subnets"]:

        subnet_data = info["subnets"][subnet]

        angle = 0.0
        SUBNET_SIZE = len(subnet_data["entities"])

        RADIUS = math.sqrt(SUBNET_SIZE) * 40.0
        for ip in subnet_data["entities"]:
            center_x = real_subnet_to_center[subnet][0] if subnet_data["type"] == "real" else guessed_subnet_to_center[subnet][0] 
            center_y = real_subnet_to_center[subnet][1] if subnet_data["type"] == "real" else guessed_subnet_to_center[subnet][1] 
            x = center_x + RADIUS * math.cos(angle * (math.pi / 180.0))
            y = center_y + RADIUS * math.sin(angle * (math.pi / 180.0))

            ip_to_position[ip]  = (x, y)
            angle += 360.0 / SUBNET_SIZE

    return ip_to_position