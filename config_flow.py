import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, OptionsFlow
from homeassistant.core import callback

from .const import DOMAIN, CONF_RELAY, CONF_RELAY_REPLIES

class RadioBrowserConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user( self, user_input ):
        return self.async_create_entry(title="GoodWe Local Server", data={})

    @staticmethod
    @callback
    def async_get_options_flow( config_entry ):
        return GoodweLocalServerOptionsFlow()


class GoodweLocalServerOptionsFlow(OptionsFlow):

    async def async_step_init( self, user_input=None ):
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Optional( CONF_RELAY, default=options.get(CONF_RELAY, False) ): bool,
                vol.Optional( CONF_RELAY_REPLIES, default=options.get(CONF_RELAY_REPLIES, False) ): bool,
            })
        )
