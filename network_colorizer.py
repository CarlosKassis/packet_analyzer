


def get_subnet_node_colors(info):

    COLORS_HEX = [ 
        "FF0000", "FF6347", "F08080", "FF8C00", "FFD700", 
        "7CFC00", "008000", "00FF00", "00FA9A", "00FFFF",
        "40E0D0", "7FFFD4", "6495ED", "1E90FF", "87CEFA",
        "000080", "0000FF", "8A2BE2", "4B0082", "8B008B",
        "BA55D3", "FF00FF", "FF1493", "FF69B4", "D2691E",
        "F4A460", "BC8F8F", "778899", "F0FFF0", "F0FFFF"]
    
    subnet_to_color = dict()

    for subnet, index in zip(info["subnets"], range(len(info["subnets"]))):
        subnet_to_color[subnet] = COLORS_HEX[index % len(COLORS_HEX)]
    
    return dict(subnet_to_color)