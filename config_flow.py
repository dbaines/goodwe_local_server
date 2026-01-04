
from homeassistant.config_entries import ConfigFlow

DOMAIN = "goodwe_local_server"

class RadioBrowserConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user( self, user_input ):
        return self.async_create_entry(title="GoodWe Local Server", data={})
