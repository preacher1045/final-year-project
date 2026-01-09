import yaml
import os


def load_yaml_config(config_path: str) -> str:  
    """
    Load PCAP configuration from a YAML file.

    Args:
        config_path (str): Path to the YAML configuration file.
    Returns:
        dict: Parsed configuration dictionary.
    """

    try:
        with open(config_path, 'r') as file:
            config_data = yaml.safe_load(file)
            return config_data
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        return None
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return None


def get_raw_data_path() -> str:
    """
    Load app_config.yaml and extract the raw data path.
    
    Returns:
        str: Path to the raw data directory.
    """
    # Construct path to config file (two levels up to project root, then into config)
    config_path = os.path.join(os.path.dirname(__file__), '../../config/app_config.yaml')
    config_path = os.path.abspath(config_path)
    
    config = load_yaml_config(config_path)

    if config:
        print("Configuration loaded successfully.")
        traffic_data_path = config['paths']['data_directory']['raw_data']
        print(f"Traffic data path: {traffic_data_path}")
        return traffic_data_path
    return None


if __name__ == '__main__':
    raw_data_path = get_raw_data_path()