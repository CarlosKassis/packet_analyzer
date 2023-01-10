

def get_ip_display_positions(info):

    positions = dict()

    index = 0
    for ip in info["entities"]:
        x = index % 10
        y = index // 10
        x *= 50
        y *= 50
        positions[ip] = (x, y)
        index += 1

    return positions