import time

class SimpleCache:
    def __init__(self, size_limit, expiration_time):
        """
        Initialize a simple cache with a specified size limit and expiration time.

        Args:
            size_limit (int): The maximum number of entries the cache can hold.
            expiration_time (float): The maximum time (in seconds) an entry can exist in the cache.
        """
        # Dictionary to store cache entries, where keys are cache keys, and values are dictionaries
        # containing 'value' (cached data) and 'timestamp' (time of entry creation)
        self.cache = {}

        # Maximum number of entries the cache can hold
        self.size_limit = size_limit

        # Maximum time an entry can exist in the cache
        self.expiration_time = expiration_time

    def add_entry(self, key, value):
        """
        Add a new entry to the cache or update an existing entry.

        Args:
            key: The key associated with the cache entry.
            value: The data to be stored in the cache.
        """
        # Store the value and the timestamp of the entry in the cache dictionary
        self.cache[key] = {'value': value, 'timestamp': time.time()}

    def get_entry(self, key):
        """
        Retrieve a cache entry based on the provided key.

        Args:
            key: The key associated with the cache entry.

        Returns:
            dict or None: A dictionary containing 'value' and 'timestamp' if the key exists, else None.
        """
        return self.cache.get(key)

    def remove_entry(self, key):
        """
        Remove a cache entry based on the provided key.

        Args:
            key: The key associated with the cache entry.
        """
        # Check if the key exists in the cache before removing it
        if key in self.cache:
            del self.cache[key]

    def is_expired(self, key):
        """
        Check if a cache entry has expired based on the expiration time.

        Args:
            key: The key associated with the cache entry.

        Returns:
            bool: True if the entry has expired, False otherwise.
        """
        # Check if the key exists in the cache and if the entry has exceeded the expiration time
        if key in self.cache:
            current_time = time.time()
            entry_time = self.cache[key]['timestamp']
            return (current_time - entry_time) > self.expiration_time
        return False

    def manage_size(self):
        """
        Manage the size of the cache by removing the oldest entry if the size exceeds the limit.
        """
        # Check if the number of entries in the cache exceeds the specified size limit
        if len(self.cache) > self.size_limit:
            # Find the key of the oldest entry based on the entry timestamp
            oldest_key = min(self.cache, key=lambda k: self.cache[k]['timestamp'])
            
            # Remove the oldest entry from the cache
            self.remove_entry(oldest_key)
