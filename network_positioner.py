import numpy as np

def get_ip_display_positions(info):

    ip_to_position = dict()

    positions = np.random.uniform([0, 0], [1500, 1500], size=(len(info["entities"]), 2))

    for ip, position in zip(info["entities"], positions):
        ip_to_position[ip] = (position[0], position[1])
    
    return ip_to_position