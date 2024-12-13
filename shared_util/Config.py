import os
from configparser import ConfigParser


class Config:
    configs = {}
    paths = {}

    @staticmethod
    def init(folder: str = ""):
        """
        Initializes the configuration file for the specified folder.

        Args:
            folder (str): The folder in which the configuration file is located.
        """
        if folder not in Config.paths:
            config_path = "config.ini"
            if not os.path.exists(config_path):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
                config_path = os.path.join(parent_dir, folder, "config.ini")

            if not os.path.exists(config_path):
                open(config_path, "w")

            Config.paths[folder] = config_path
            config_parser = ConfigParser()
            config_parser.read(config_path)
            Config.configs[folder] = config_parser

    @staticmethod
    def get(section: str, key: str, default_return: str = "", folder: str = ""):
        """
        Retrieve the value of a configuration key from the specified section and folder.

        Args:
            section (str): The section name in the configuration file.
            key (str): The key name in the specified section.
            folder (str): The folder in which the configuration file is located.

        Returns:
            str: The value associated with the specified key in the specified section.
        """
        Config.init(folder)

        return Config.configs[folder].get(section, key, fallback=default_return)

    @staticmethod
    def set(section: str, key: str, value: str, folder: str = ""):
        """
        Sets the value of a key in the specified section of the configuration file in the specified folder.

        Args:
            section (str): The section in the configuration file.
            key (str): The key to set the value for.
            value (str): The value to set for the key.
            folder (str): The folder in which the configuration file is located.
        """
        Config.init(folder)

        if not Config.configs[folder].has_section(section):
            Config.configs[folder].add_section(section)

        Config.configs[folder].set(section, key, value)
        with open(Config.paths[folder], "w") as configfile:
            Config.configs[folder].write(configfile)

    @staticmethod
    def get_items_from_section(section: str, folder: str = ""):
        """
        Retrieves all items from the specified section in the configuration file in the specified folder.

        Args:
            section (str): The name of the section in the configuration.
            folder (str): The folder in which the configuration file is located.

        Returns:
            list: A list of tuples containing the items from the specified section.
        """
        Config.init(folder)

        return Config.configs[folder].items(section)

    @staticmethod
    def get_values_from_section(section: str, folder: str = ""):
        """
        Retrieves all values from the specified section in the configuration file in the specified folder.

        Args:
            section (str): The name of the section in the configuration.
            folder (str): The folder in which the configuration file is located.

        Returns:
            list: A list of values from the specified section.
        """
        if folder not in Config.configs:
            Config.init(folder)

        return [value for key, value in Config.configs[folder].items(section)]
