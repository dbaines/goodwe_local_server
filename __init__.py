
async def async_setup_entry( hass, config_entry ):
    await hass.config_entries.async_forward_entry_setups( config_entry, ["sensor"] )
    return True
