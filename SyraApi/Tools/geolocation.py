"""
Utilitários para cálculos de geolocalização
Usa a fórmula de Haversine para calcular distâncias entre coordenadas
"""

import math
from typing import Tuple, List
from datetime import datetime, timedelta

# Raio da Terra em metros
EARTH_RADIUS_METERS = 6371000

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calcula a distância entre dois pontos geográficos usando a fórmula de Haversine
    
    Args:
        lat1, lon1: Coordenadas do primeiro ponto (latitude, longitude)
        lat2, lon2: Coordenadas do segundo ponto (latitude, longitude)
    
    Returns:
        Distância em metros
    """
    # Converte graus para radianos
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)
    
    # Diferenças
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    
    # Fórmula de Haversine
    a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Distância em metros
    distance = EARTH_RADIUS_METERS * c
    
    return distance


def is_within_radius(lat1: float, lon1: float, lat2: float, lon2: float, radius_meters: float) -> bool:
    """
    Verifica se dois pontos estão dentro de um raio especificado
    
    Args:
        lat1, lon1: Coordenadas do primeiro ponto
        lat2, lon2: Coordenadas do segundo ponto
        radius_meters: Raio em metros
    
    Returns:
        True se os pontos estão dentro do raio, False caso contrário
    """
    distance = haversine_distance(lat1, lon1, lat2, lon2)
    return distance <= radius_meters


def get_bounding_box(lat: float, lon: float, radius_meters: float) -> Tuple[float, float, float, float]:
    """
    Calcula uma bounding box (caixa delimitadora) ao redor de um ponto
    
    Args:
        lat, lon: Coordenadas centrais
        radius_meters: Raio em metros
    
    Returns:
        Tupla (min_lat, max_lat, min_lon, max_lon)
    """
    # Graus de latitude por metro (aproximado)
    lat_degree_per_meter = 1 / 111320
    
    # Graus de longitude por metro (varia com a latitude)
    lon_degree_per_meter = 1 / (111320 * math.cos(math.radians(lat)))
    
    # Calcula os limites
    min_lat = lat - (radius_meters * lat_degree_per_meter)
    max_lat = lat + (radius_meters * lat_degree_per_meter)
    min_lon = lon - (radius_meters * lon_degree_per_meter)
    max_lon = lon + (radius_meters * lon_degree_per_meter)
    
    return (min_lat, max_lat, min_lon, max_lon)


def format_distance(distance_meters: float) -> str:
    """
    Formata distância para exibição legível
    
    Args:
        distance_meters: Distância em metros
    
    Returns:
        String formatada (ex: "150m", "2.5km")
    """
    if distance_meters < 1000:
        return f"{int(distance_meters)}m"
    else:
        return f"{distance_meters/1000:.1f}km"


def calculate_expiration_time(duration_minutes: int) -> datetime:
    """
    Calcula o tempo de expiração baseado na duração
    
    Args:
        duration_minutes: Duração em minutos
    
    Returns:
        Datetime de expiração
    """
    return datetime.utcnow() + timedelta(minutes=duration_minutes)


def is_expired(expiration_time: datetime) -> bool:
    """
    Verifica se um tempo já expirou
    
    Args:
        expiration_time: Datetime de expiração
    
    Returns:
        True se expirado, False caso contrário
    """
    return datetime.utcnow() > expiration_time


def validate_coordinates(latitude: float, longitude: float) -> bool:
    """
    Valida se as coordenadas são válidas
    
    Args:
        latitude: Latitude (-90 a 90)
        longitude: Longitude (-180 a 180)
    
    Returns:
        True se válidas, False caso contrário
    """
    return -90 <= latitude <= 90 and -180 <= longitude <= 180


def get_center_point(coordinates: List[Tuple[float, float]]) -> Tuple[float, float]:
    """
    Calcula o ponto central de uma lista de coordenadas
    
    Args:
        coordinates: Lista de tuplas (latitude, longitude)
    
    Returns:
        Tupla (latitude_central, longitude_central)
    """
    if not coordinates:
        return (0.0, 0.0)
    
    total_lat = sum(coord[0] for coord in coordinates)
    total_lon = sum(coord[1] for coord in coordinates)
    
    count = len(coordinates)
    
    return (total_lat / count, total_lon / count)


def bearing_between_points(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calcula o ângulo de direção entre dois pontos (bearing)
    
    Args:
        lat1, lon1: Coordenadas do primeiro ponto
        lat2, lon2: Coordenadas do segundo ponto
    
    Returns:
        Ângulo em graus (0-360, onde 0=Norte, 90=Leste, 180=Sul, 270=Oeste)
    """
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    dlon_rad = math.radians(lon2 - lon1)
    
    x = math.sin(dlon_rad) * math.cos(lat2_rad)
    y = math.cos(lat1_rad) * math.sin(lat2_rad) - math.sin(lat1_rad) * math.cos(lat2_rad) * math.cos(dlon_rad)
    
    bearing_rad = math.atan2(x, y)
    bearing_deg = math.degrees(bearing_rad)
    
    # Normaliza para 0-360
    bearing_deg = (bearing_deg + 360) % 360
    
    return bearing_deg


def get_direction_name(bearing: float) -> str:
    """
    Converte um bearing em nome de direção
    
    Args:
        bearing: Ângulo em graus (0-360)
    
    Returns:
        Nome da direção (N, NE, E, SE, S, SW, W, NW)
    """
    directions = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW']
    index = round(bearing / 45) % 8
    return directions[index]
